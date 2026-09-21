program tinySSL_test;

{ ============================================================================
  Programme de test automatisé pour opensslutils (OpenSSL 3.0)
  Teste toutes les fonctions dans un workflow logique :
    1. Génération de clés et certificats
    2. Manipulation de certificats
    3. Cryptographie symétrique et asymétrique
    4. Conversions de formats
    5. Utilitaires
  ============================================================================ }

{$mode objfpc}{$H+}
{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Windows, SysUtils, Classes,
  opensslutils,
  utils;

// ============================================================================
// Compteurs globaux de résultats
// ============================================================================
var
  g_pass : integer = 0;
  g_fail : integer = 0;
  g_skip : integer = 0;

  // Retourne la taille d'un fichier, 0 si absent
  function GetFileSize_(const filename: string): Int64;
  var sr: TSearchRec;
  begin
    result := 0;
    if FindFirst(filename, faAnyFile, sr) = 0 then
    begin
      result := sr.Size;
      FindClose(sr);
    end;
  end;


// ============================================================================
// Helpers d'affichage
// ============================================================================

procedure Banner(const title: string);
begin
  WriteLn;
  WriteLn('════════════════════════════════════════════════════════');
  WriteLn('  ' + title);
  WriteLn('════════════════════════════════════════════════════════');
end;

procedure Section(const title: string);
begin
  WriteLn;
  WriteLn('── ' + title + ' ──');
end;

procedure Check(const testName: string; result: boolean; const expected: boolean = true);
begin
  if result = expected then
  begin
    WriteLn('  [PASS] ' + testName);
    Inc(g_pass);
  end
  else
  begin
    WriteLn('  [FAIL] ' + testName);
    Inc(g_fail);
  end;
end;

procedure CheckFile(const testName, filename: string);
begin
  if FileExists(filename) and (GetFileSize_(filename) > 0) then
  begin
    WriteLn('  [PASS] ' + testName + ' → ' + filename +
            ' (' + IntToStr(GetFileSize_(filename)) + ' bytes)');
    Inc(g_pass);
  end
  else
  begin
    WriteLn('  [FAIL] ' + testName + ' → fichier absent ou vide: ' + filename);
    Inc(g_fail);
  end;
end;

procedure Skip(const testName, reason: string);
begin
  WriteLn('  [SKIP] ' + testName + ' (' + reason + ')');
  Inc(g_skip);
end;



// Lit le contenu d'un fichier texte
function ReadFileContent(const filename: string): string;
var
  sl: TStringList;
begin
  result := '';
  if not FileExists(filename) then Exit;
  sl := TStringList.Create;
  try
    sl.LoadFromFile(filename);
    result := sl.Text;
  finally
    sl.Free;
  end;
end;

// Supprime les fichiers de test
procedure Cleanup(const files: array of string);
var f: string;
begin
  for f in files do
    if FileExists(f) then DeleteFile(f);
end;

// ============================================================================
// Tests
// ============================================================================

procedure Test_LoadSSL;
begin
  Section('LoadSSL / FreeSSL');
  Check('LoadSSL', LoadSSL);
  FreeSSL;
  Check('LoadSSL (2e appel)', LoadSSL);   // doit être idempotent
end;

// ----------------------------------------------------------------------------
procedure Test_GenerateKey;
begin
  Section('generate_rsa_key_2 → public.pem + private.pem');
  Cleanup(['public.pem', 'private.pem']);
  Check('generate_rsa_key_2', generate_rsa_key_2);
  CheckFile('public.pem créé',  'public.pem');
  CheckFile('private.pem créé', 'private.pem');
end;

// ----------------------------------------------------------------------------
procedure Test_MkCert_RSA;
begin
  Section('mkcert RSA (CA)');
  Cleanup(['ca_rsa.crt', 'ca_rsa.key']);
  Check('mkcert RSA CA',
    mkcert('ca_rsa.crt', 'Test CA RSA', '', 'secret', '', true, 'RSA'));
  CheckFile('ca_rsa.crt', 'ca_rsa.crt');
  CheckFile('ca_rsa.key', 'ca_rsa.key');
end;

procedure Test_MkCert_EC;
begin
  Section('mkcert EC P-256');
  Cleanup(['ca_ec.crt', 'ca_ec.key']);
  Check('mkcert EC CA',
    mkcert('ca_ec.crt', 'Test CA EC', '', 'secret', '', true, 'EC'));
  CheckFile('ca_ec.crt', 'ca_ec.crt');
  CheckFile('ca_ec.key', 'ca_ec.key');
end;

procedure Test_MkCert_EC384;
begin
  Section('mkcert EC P-384');
  Cleanup(['ca_ec384.crt', 'ca_ec384.key']);
  Check('mkcert EC384 CA',
    mkcert('ca_ec384.crt', 'Test CA EC384', '', 'secret', '', true, 'EC384'));
  CheckFile('ca_ec384.crt', 'ca_ec384.crt');
  CheckFile('ca_ec384.key', 'ca_ec384.key');
end;

procedure Test_MkCert_ED25519;
begin
  Section('mkcert ED25519');
  Cleanup(['ca_ed.crt', 'ca_ed.key']);
  Check('mkcert ED25519',
    mkcert('ca_ed.crt', 'Test CA ED25519', '', 'secret', '', true, 'ED25519'));
  CheckFile('ca_ed.crt', 'ca_ed.crt');
  CheckFile('ca_ed.key', 'ca_ed.key');
end;

// ----------------------------------------------------------------------------
procedure Test_MkReq;
begin
  Section('mkreq → CSR + clé');
  Cleanup(['server.csr', 'server.key']);
  Check('mkreq',
    mkreq('www.example.com', '', 'server.csr'));
  CheckFile('server.csr créé', 'server.csr');
  CheckFile('server.key créé', 'server.key');
end;

procedure Test_MkReq_ReuseKey;
begin
  Section('mkreq avec clé existante');
  Cleanup(['server2.csr']);
  if not FileExists('server.key') then
  begin
    Skip('mkreq (clé réutilisée)', 'server.key absent');
    Exit;
  end;
  Check('mkreq clé réutilisée',
    mkreq('myapp.local', 'server.key', 'server2.csr'));
  CheckFile('server2.csr créé', 'server2.csr');
end;

// ----------------------------------------------------------------------------
procedure Test_SignReq;
begin
  Section('signreq → certificat signé par la CA RSA');
  Cleanup(['server.crt']);
  if not FileExists('ca_rsa.crt') or not FileExists('server.csr') then
  begin
    Skip('signreq', 'ca_rsa.crt ou server.csr absent');
    Exit;
  end;
  Check('signreq (sans SAN)',
    signreq('server.csr', 'ca_rsa.crt', 'secret', '', false));
  CheckFile('server.crt créé', 'server.crt');
end;

procedure Test_SignReq_WithSAN;
begin
  Section('signreq avec Subject Alternative Names');
  Cleanup(['server_san.crt', 'server2.csr']);
  if not FileExists('ca_rsa.crt') then
  begin
    Skip('signreq+SAN', 'ca_rsa.crt absent');
    Exit;
  end;
  // Nouveau CSR pour avoir un fichier propre
  mkreq('san.example.com', '', 'server2.csr');
  Check('signreq avec SAN DNS+IP',
    signreq('server2.csr', 'ca_rsa.crt', 'secret',
            'DNS:*.example.com,DNS:san.example.com,IP:127.0.0.1', false));
  // signreq écrit dans server2.crt
  CheckFile('server2.crt créé', 'server2.crt');
end;

// ----------------------------------------------------------------------------
procedure Test_Verify;
begin
  Section('verify_certificate');
  if not FileExists('server.crt') or not FileExists('ca_rsa.crt') then
  begin
    Skip('verify', 'server.crt ou ca_rsa.crt absent');
    Exit;
  end;
  Check('verify server.crt par ca_rsa.crt',
    verify_certificate('server.crt', 'ca_rsa.crt'));
  // Vérification négative : cert signé par mauvaise CA
  if FileExists('ca_ec.crt') then
    Check('verify (mauvaise CA → doit échouer)',
      verify_certificate('server.crt', 'ca_ec.crt'), false);
end;

// ----------------------------------------------------------------------------
procedure Test_PrintCert;
begin
  Section('print_cert');
  if not FileExists('ca_rsa.crt') then begin Skip('print_cert', 'ca_rsa.crt absent'); Exit; end;
  WriteLn('  --- Détails ca_rsa.crt ---');
  Check('print_cert', print_cert('ca_rsa.crt'));
end;

procedure Test_PrintPrivate;
begin
  Section('print_private');
  if not FileExists('ca_rsa.key') then begin Skip('print_private', 'ca_rsa.key absent'); Exit; end;
  WriteLn('  --- Détails ca_rsa.key ---');
  Check('print_private (sans mot de passe)', print_private('ca_rsa.key','secret'));
end;

procedure Test_PrintRequest;
begin
  Section('print_req');
  if not FileExists('server.csr') then begin Skip('print_req', 'server.csr absent'); Exit; end;
  WriteLn('  --- Détails server.csr ---');
  Check('print_req', print_req('server.csr'));
end;

procedure Test_PrintSSHKey;
begin
  Section('PrintSSHKey (RSA)');
  if not FileExists('public.pem') then begin Skip('PrintSSHKey RSA', 'public.pem absent'); Exit; end;
  WriteLn('  --- OpenSSH public key ---');
  Check('PrintSSHKey RSA', PrintSSHKey('public.pem'));

  {
  Section('PrintSSHKey (EC P-256)');
  if not FileExists('ca_ec.key') then begin Skip('PrintSSHKey EC', 'ca_ec.key absent'); Exit; end;
  Check('PrintSSHKey EC', PrintSSHKey('ca_ec.key'));

  Section('PrintSSHKey (EC P-384)');
  if not FileExists('ca_ec384.key') then begin Skip('PrintSSHKey EC384', 'ca_ec384.key absent'); Exit; end;
  Check('PrintSSHKey EC384', PrintSSHKey('ca_ec384.key'));
  }
end;

// ----------------------------------------------------------------------------
procedure Test_SetPassword;
var content1, content2: string;
begin
  Section('set_password');
  if not FileExists('server.key') then begin Skip('set_password', 'server.key absent'); Exit; end;

  // Copie de la clé originale (en clair car générée sans mot de passe)
  content1 := ReadFileContent('server.key');

  // Ajout d'un mot de passe
  Check('set_password (ajout password)',
    set_password('server.key', 'secret'));

  // La clé chiffrée doit contenir ENCRYPTED
  content2 := ReadFileContent('new_server.key');
  Check('clé contient ENCRYPTED après set_password',
    Pos('ENCRYPTED', content2) > 0);

  // Suppression du mot de passe
  Check('set_password (suppression password)',
    set_password('new_server.key', ''));

  // La clé en clair ne doit plus contenir ENCRYPTED
  content2 := ReadFileContent('new_new_server.key');
  Check('clé sans ENCRYPTED après suppression',
    Pos('ENCRYPTED', content2) = 0);
end;

// ----------------------------------------------------------------------------
procedure Test_Hash;
var input: array of byte;
begin
  Section('hash');
  SetLength(input, 5);
  input[0] := Ord('h'); input[1] := Ord('e'); input[2] := Ord('l');
  input[3] := Ord('l'); input[4] := Ord('o');

  WriteLn('  Input: "hello"');
  WriteLn('  Expected SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  Check('hash SHA-256', hash('SHA-256', input));

  WriteLn('  Expected SHA-512: (long)');
  Check('hash SHA-512', hash('SHA-512', input));

  WriteLn('  Expected SHA3-256:');
  Check('hash SHA3-256', hash('SHA3-256', input));

  WriteLn('  Expected MD5 (legacy provider requis):');
  Check('hash MD5', hash('MD5', input));
end;

// ----------------------------------------------------------------------------
procedure Test_Base64;
var input: array of byte;
begin
  Section('Base64Encode / Base64Decode');
  SetLength(input, 11);
  input[0]  := Ord('H'); input[1]  := Ord('e'); input[2]  := Ord('l');
  input[3]  := Ord('l'); input[4]  := Ord('o'); input[5]  := Ord(' ');
  input[6]  := Ord('W'); input[7]  := Ord('o'); input[8]  := Ord('r');
  input[9]  := Ord('l'); input[10] := Ord('d');

  WriteLn('  Input: "Hello World"');
  WriteLn('  Expected Base64: SGVsbG8gV29ybGQ=');
  Check('Base64Encode', Base64Encode(input));

  WriteLn('  Decode SGVsbG8gV29ybGQ=:');
  Check('Base64Decode', Base64Decode('SGVsbG8gV29ybGQ='));
end;

// ----------------------------------------------------------------------------
procedure Test_Crypt_AES256;
var key, iv: string;
begin
  Section('crypt AES-256-CBC chiffrement + déchiffrement');

  // Chiffrement avec clé et IV aléatoires (générés par crypt si absents)
  WriteLn('  --- Chiffrement "Hello OpenSSL 3.0" ---');
  Check('encrypt AES-256-CBC (clé aléatoire)',
    crypt('AES-256-CBC', 'Hello OpenSSL 3.0', '', '', 1));

  // Chiffrement avec clé et IV explicites (32 et 16 octets en hex)
  key := '0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20';
  iv  := '0102030405060708090A0B0C0D0E0F10';
  WriteLn('  --- Chiffrement avec clé fixe ---');
  Check('encrypt AES-256-CBC (clé fixe)',
    crypt('AES-256-CBC', 'Hello', key, iv, 1));

  Section('crypt ChaCha20-Poly1305');
  Check('encrypt ChaCha20-Poly1305',
    crypt('ChaCha20-Poly1305', 'Hello', '', '', 1));

  Section('crypt AES-128-GCM');
  Check('encrypt AES-128-GCM',
    crypt('AES-128-GCM', 'Hello', '', '', 1));
end;

// ----------------------------------------------------------------------------
procedure Test_EncryptDecrypt_RSA;
var encrypted,decrypted: string;
begin
  Section('Encrypt_Pub / Decrypt_Priv (RSA PKCS#1)');
  if not FileExists('public.pem') or not FileExists('private.pem') then
  begin
    Skip('Encrypt_Pub/Decrypt_Priv', 'public.pem ou private.pem absent');
    Exit;
  end;

  encrypted := '';
  Check('Encrypt_Pub',
    Encrypt_Pub('Message secret test 1234', encrypted));
  WriteLn('  Chiffré (Base64): ' + Copy(encrypted, 1, 40) + '...');

  if encrypted <> '' then
  begin
    WriteLn('  --- Déchiffrement ---');
    Check('Decrypt_Priv', Decrypt_Priv(encrypted,decrypted));
    writeln('Dechiffré : '+decrypted );
  end;
end;

// ----------------------------------------------------------------------------
procedure Test_PEM2P7B;
begin
  Section('PEM2P7B / P7B2PEM');
  if not FileExists('ca_rsa.crt') then begin Skip('PEM2P7B', 'ca_rsa.crt absent'); Exit; end;

  Cleanup(['ca_rsa.p7b']);
  Check('PEM2P7B', PEM2P7B('ca_rsa.crt'));
  CheckFile('ca_rsa.p7b créé', 'ca_rsa.p7b');

  if FileExists('ca_rsa.p7b') then
  begin
    Cleanup(['ca_rsa_fromP7B.crt']);
    // P7B2PEM écrit dans le même répertoire avec extension .crt
    Check('P7B2PEM', P7B2PEM('ca_rsa.p7b'));
  end;
end;

procedure Test_PEM2PFX;
begin
  Section('PEM2PFX / PFX2PEM');
  if not FileExists('ca_rsa.crt') or not FileExists('ca_rsa.key') then
  begin
    Skip('PEM2PFX', 'ca_rsa.crt ou ca_rsa.key absent');
    Exit;
  end;

  Cleanup(['ca_rsa.pfx']);
  Check('PEM2PFX', PEM2PFX('testpfxpwd', 'ca_rsa.key', 'ca_rsa.crt','secret'));
  CheckFile('ca_rsa.pfx créé', 'ca_rsa.pfx');

  if FileExists('ca_rsa.pfx') then
  begin
    Cleanup(['ca_rsa_fromPFX.crt', 'ca_rsa_fromPFX.key']);
    Check('PFX2PEM', PFX2PEM('ca_rsa.pfx', 'testpfxpwd'));
  end;
end;

procedure Test_DER;
begin
  Section('X509PEM2DER / X509DER2PEM');
  if not FileExists('ca_rsa.crt') then begin Skip('X509PEM2DER', 'ca_rsa.crt absent'); Exit; end;

  Cleanup(['ca_rsa.der']);
  Check('X509PEM2DER', X509PEM2DER('ca_rsa.crt'));
  CheckFile('ca_rsa.der créé', 'ca_rsa.der');

  if FileExists('ca_rsa.der') then
  begin
    Check('X509DER2PEM', X509DER2PEM('ca_rsa.der'));
  end;

  Section('PVTPEM2DER / PVTDER2PEM');
  if not FileExists('ca_rsa.key') then begin Skip('PVTPEM2DER', 'ca_rsa.key absent'); Exit; end;

  Cleanup(['ca_rsa_pvt.der']);
  Check('PVTPEM2DER', PVTPEM2DER('ca_rsa.key'));
  // PVTPEM2DER écrit dans ca_rsa.der (même nom, extension .der)
  CheckFile('ca_rsa.der (clé privée)', 'ca_rsa.der');
end;

// ----------------------------------------------------------------------------
procedure Test_ListAlgos;
begin
  Section('list_ciphers');
  WriteLn('  (liste les algorithmes disponibles via le provider default)');
  Check('list_ciphers', list_ciphers);

  Section('list_hashes');
  Check('list_hashes', list_hashes);
end;

// ----------------------------------------------------------------------------
procedure Test_Workflow_Complete;
begin
  Section('WORKFLOW COMPLET : CA RSA → CSR → Cert signé → Vérification');

  Cleanup(['wf_ca.crt', 'wf_ca.key', 'wf_server.csr', 'wf_server.key', 'wf_server.crt']);

  // Étape 1 : CA
  Check('1. mkcert CA RSA',
    mkcert('wf_ca.crt', 'Workflow CA', '', 'secret', '', true, 'RSA'));
  CheckFile('   wf_ca.crt', 'wf_ca.crt');

  // Étape 2 : CSR
  if FileExists('wf_ca.crt') then
    Check('2. mkreq serveur',
      mkreq('wf.example.com', '', 'wf_server.csr'));
  CheckFile('   wf_server.csr', 'wf_server.csr');

  // Étape 3 : Signature
  if FileExists('wf_ca.crt') and FileExists('wf_server.csr') then
    Check('3. signreq',
      signreq('wf_server.csr', 'wf_ca.crt', 'secret',
              'DNS:wf.example.com,DNS:*.wf.example.com', false));
  CheckFile('   wf_server.crt', 'wf_server.crt');

  // Étape 4 : Vérification
  if FileExists('wf_server.crt') and FileExists('wf_ca.crt') then
    Check('4. verify_certificate',
      verify_certificate('wf_server.crt', 'wf_ca.crt'));

  // Étape 5 : Inspection
  if FileExists('wf_server.crt') then
    Check('5. print_cert', print_cert('wf_server.crt'));
end;

procedure Test_Workflow_EC;
begin
  Section('WORKFLOW COMPLET : CA EC384 → CSR → Cert signé → Vérification');

  Cleanup(['wf_ec_ca.crt', 'wf_ec_ca.key', 'wf_ec_server.csr',
           'wf_ec_server.key', 'wf_ec_server.crt']);

  Check('1. mkcert CA EC384',
    mkcert('wf_ec_ca.crt', 'Workflow EC384 CA', '', '', '', true, 'EC384'));
  CheckFile('   wf_ec_ca.crt', 'wf_ec_ca.crt');

  if FileExists('wf_ec_ca.crt') then
    Check('2. mkreq (EC384)',
      mkreq('ec.example.com', '', 'wf_ec_server.csr'));

  if FileExists('wf_ec_ca.crt') and FileExists('wf_ec_server.csr') then
    Check('3. signreq',
      signreq('wf_ec_server.csr', 'wf_ec_ca.crt', '',
              'DNS:ec.example.com', false));

  if FileExists('wf_ec_server.crt') and FileExists('wf_ec_ca.crt') then
    Check('4. verify_certificate',
      verify_certificate('wf_ec_server.crt', 'wf_ec_ca.crt'));
end;

// ----------------------------------------------------------------------------
procedure PrintSummary;
var total: integer;
begin
  total := g_pass + g_fail + g_skip;
  Banner('RÉSULTATS');
  WriteLn(Format('  Total  : %d', [total]));
  WriteLn(Format('  PASS   : %d', [g_pass]));
  WriteLn(Format('  FAIL   : %d', [g_fail]));
  WriteLn(Format('  SKIP   : %d', [g_skip]));
  WriteLn;
  if g_fail = 0 then
    WriteLn('  ✓ Tous les tests passent.')
  else
    WriteLn(Format('  ✗ %d test(s) en échec.', [g_fail]));
  WriteLn;
end;

// ============================================================================
// Main
// ============================================================================
begin
  Banner('tinySSL_test — OpenSSL 3.0');
  WriteLn('  Répertoire courant : ' + GetCurrentDir);
  WriteLn('  Fichier ini        : tinyssl.ini');
  WriteLn;

  // Initialisation OpenSSL — requis pour tous les tests cryptographiques
  if not LoadSSL then
  begin
    WriteLn('[FATAL] Impossible de charger OpenSSL. Vérifiez libcrypto-3-x64.dll.');
    Halt(1);
  end;

  try
    // --- Génération de clés et certificats ---
    Test_GenerateKey;
    Test_MkCert_RSA;
    Test_MkCert_EC;
    Test_MkCert_EC384;
    Test_MkCert_ED25519;

    // --- PKI workflow ---
    Test_MkReq;
    Test_MkReq_ReuseKey;
    Test_SignReq;
    Test_SignReq_WithSAN;
    Test_Verify;

    // --- Inspection ---
    Test_PrintCert;
    Test_PrintPrivate;
    Test_PrintRequest;
    Test_PrintSSHKey;

    // --- Gestion de clés ---
    Test_SetPassword;

    // --- Cryptographie ---
    Test_Hash;
    Test_Base64;
    Test_Crypt_AES256;
    Test_EncryptDecrypt_RSA;

    // --- Conversions de formats ---
    Test_PEM2P7B;
    Test_PEM2PFX;
    Test_DER;

    // --- Liste des algorithmes ---
    Test_ListAlgos;

    // --- Workflows complets ---
    Test_Workflow_Complete;
    //Test_Workflow_EC;

  finally
    FreeSSL;
  end;

  PrintSummary;

  if g_fail > 0 then Halt(1) else Halt(0);
end.
