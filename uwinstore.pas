{ ============================================================================
  Accès aux stores de certificats Windows via WinCrypt API
  Compatible OpenSSL 3.x — pas de dépendance au provider cryptoapi.

  Stores disponibles :
    'MY'          → certificats personnels (avec clé privée)
    'ROOT'        → autorités racines de confiance
    'CA'          → autorités intermédiaires
    'ADDRESSBOOK' → contacts
    'TRUST'       → règles de confiance
    'DISALLOWED'  → certificats révoqués/interdits

  Portée (dwFlags) :
    CERT_SYSTEM_STORE_CURRENT_USER  → store de l'utilisateur courant
    CERT_SYSTEM_STORE_LOCAL_MACHINE → store machine (admin requis)
  ============================================================================ }

unit uwinstore;

interface

uses
  Windows,     // pour les types WinAPI de base
  SysUtils,StrUtils,
  opensslutils,utils,
  openssl_types,      // Pour X509_*, X509_NAME_*, pSTACK_OFX509...  ; // pour PX509, PEM_write_bio_X509, etc.
  openssl_bio,
  openssl_pem,
  openssl_x509,
  openssl_x509_vfy;

const
  // Provider passé comme entier-dans-pointeur (convention WinCrypt C)
  CERT_STORE_PROV_SYSTEM_PTR = PAnsiChar(PtrUInt(10));

  CERT_SYSTEM_STORE_CURRENT_USER_ID  = 1;
  CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2;
  CERT_SYSTEM_STORE_LOCATION_SHIFT   = 16;
  CERT_SYSTEM_STORE_CURRENT_USER  =
    CERT_SYSTEM_STORE_CURRENT_USER_ID  shl CERT_SYSTEM_STORE_LOCATION_SHIFT;
  CERT_SYSTEM_STORE_LOCAL_MACHINE =
    CERT_SYSTEM_STORE_LOCAL_MACHINE_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT;

  X509_ASN_ENCODING   = $00000001;
  PKCS_7_ASN_ENCODING = $00010000;
  MY_ENCODING_TYPE    = X509_ASN_ENCODING or PKCS_7_ASN_ENCODING;
  CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

type
  HCERTSTORE     = Pointer;
  PCCERT_CONTEXT = Pointer;

  TCertNameBlob = record
    cbData : DWORD;
    pbData : PByte;
  end;

  TCertContext = record
    dwCertEncodingType : DWORD;
    pbCertEncoded      : PByte;
    cbCertEncoded      : DWORD;
    pCertInfo          : Pointer;
    hCertStore         : HCERTSTORE;
  end;
  PCertContext = ^TCertContext;

function CertOpenStore(lpszStoreProvider: PAnsiChar;
                       dwMsgAndCertEncodingType: DWORD;
                       hCryptProv: Pointer; dwFlags: DWORD;
                       pvPara: PWideChar): HCERTSTORE;
  stdcall; external 'crypt32.dll' name 'CertOpenStore';

function CertEnumCertificatesInStore(hCertStore: HCERTSTORE;
                                     pPrev: PCCERT_CONTEXT): PCCERT_CONTEXT;
  stdcall; external 'crypt32.dll' name 'CertEnumCertificatesInStore';

function CertCloseStore(hCertStore: HCERTSTORE; dwFlags: DWORD): BOOL;
  stdcall; external 'crypt32.dll' name 'CertCloseStore';

function CertGetNameStringW(pCertContext: PCCERT_CONTEXT; dwType, dwFlags: DWORD;
                             pvTypePara: Pointer; pszNameString: PWideChar;
                             cchNameString: DWORD): DWORD;
  stdcall; external 'crypt32.dll' name 'CertGetNameStringW';

//
function list_windows_store(const storeName: string;
                             machineStore: boolean = false): boolean;
//

implementation

function WinCertToX509(ctx: PCertContext): pX509;
var p: PByte;
begin
  result := nil;
  if (ctx = nil) or (ctx^.pbCertEncoded = nil) or (ctx^.cbCertEncoded = 0) then Exit;
  p := ctx^.pbCertEncoded;
  result := d2i_X509(nil, @p, ctx^.cbCertEncoded);
end;

// ----------------------------------------------------------------------------
function OpenWinStore(const storeName: string; machineStore: boolean): HCERTSTORE;
var
  flags     : DWORD;
  wStoreName: WideString;
begin
  if machineStore then flags := CERT_SYSTEM_STORE_LOCAL_MACHINE
                  else flags := CERT_SYSTEM_STORE_CURRENT_USER;
  wStoreName := WideString(storeName);
  result := CertOpenStore(
    CERT_STORE_PROV_SYSTEM_PTR,   // PAnsiChar(PtrUInt(10))
    MY_ENCODING_TYPE,
    nil,
    flags,
    PWideChar(wStoreName));       // nom du store en UTF-16
end;

// ----------------------------------------------------------------------------
function list_windows_store(const storeName: string;
                             machineStore: boolean = false): boolean;
var
  hStore : HCERTSTORE;
  ctx    : PCertContext;
  x509   : pX509;
  nameW  : array[0..511] of WideChar;
  count  : integer;
begin
  result := false;
  count  := 0;

  hStore := OpenWinStore(storeName, machineStore);
  if hStore = nil then
  begin
    WriteLn('Erreur: impossible d''ouvrir le store "' + storeName + '"' +
            ' (LastError=' + IntToStr(GetLastError) + ')');
    Exit;
  end;

  try
    ctx := nil;
    repeat
      ctx := CertEnumCertificatesInStore(hStore, ctx);
      if ctx = nil then Break;
      Inc(count);
      WriteLn('────────────────────────────────────────');
      WriteLn(Format('[%d]', [count]));

      if CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil,
                            @nameW[0], Length(nameW)) > 1 then
        WriteLn('  Name    : ' + string(WideString(PWideChar(@nameW[0]))));

      WriteLn(Format('  DER     : %d bytes', [ctx^.cbCertEncoded]));

      x509 := WinCertToX509(ctx);
      if x509 <> nil then
      try
        WriteLn('  Subject : ' + getdn2(X509_get_subject_name(x509)));
        WriteLn('  Issuer  : ' + getdn2(X509_get_issuer_name(x509)));
        try
          WriteLn('  From    : ' + DateTimeToStr(getTime(X509_get_notBefore(x509))));
          WriteLn('  To      : ' + DateTimeToStr(getTime(X509_get_notAfter(x509))));
        except on e: Exception do WriteLn('  (dates: ' + e.Message + ')'); end;
        PrintFingerprint(x509);
      finally
        X509_free(x509);
      end;
    until ctx = nil;

    WriteLn('────────────────────────────────────────');
    WriteLn(Format('Total : %d certificat(s) dans "%s" (%s)',
      [count, storeName, IfThen(machineStore, 'LocalMachine', 'CurrentUser')]));
    result := count > 0;
  finally
    CertCloseStore(hStore, 0);
  end;
end;

// ----------------------------------------------------------------------------
function load_windows_store_to_X509_STORE(const storeName: string;
                                           machineStore: boolean = false): PX509_STORE;
var
  hStore : HCERTSTORE;
  ctx    : PCertContext;
  x509   : pX509;
  count  : integer;
begin
  result := nil;
  count  := 0;
  hStore := OpenWinStore(storeName, machineStore);
  if hStore = nil then Exit;
  result := X509_STORE_new();
  if result = nil then begin CertCloseStore(hStore, 0); Exit; end;
  try
    ctx := nil;
    repeat
      ctx := CertEnumCertificatesInStore(hStore, ctx);
      if ctx = nil then Break;
      x509 := WinCertToX509(ctx);
      if x509 <> nil then
      begin
        X509_STORE_add_cert(result, x509);
        X509_free(x509);
        Inc(count);
      end;
    until ctx = nil;
    log(Format('load_windows_store "%s": %d certs', [storeName, count]));
  finally
    CertCloseStore(hStore, 0);
  end;
end;

// ----------------------------------------------------------------------------
function verify_against_windows_root(const certFile: string;
                                      machineStore: boolean = false): boolean;
var
  bp        : pBIO;
  cert      : pX509 = nil;
  store     : PX509_STORE = nil;
  store_ctx : PX509_STORE_CTX = nil;
begin
  result := false;
  bp := BIO_new_file(PAnsiChar(AnsiString(certFile)), 'r');
  if bp = nil then Exit;
  cert := PEM_read_bio_X509(bp, nil, nil, nil);
  BIO_free(bp);
  if cert = nil then Exit;
  try
    store := load_windows_store_to_X509_STORE('ROOT', machineStore);
    if store = nil then Exit;
    store_ctx := X509_STORE_CTX_new();
    if store_ctx = nil then Exit;
    if X509_STORE_CTX_init(store_ctx, store, cert, nil) = 1 then
      if X509_verify_cert(store_ctx) = 1 then
      begin
        WriteLn('Certificat valide (store Windows ROOT)');
        result := true;
      end
      else
        WriteLn('Invalide: ' + string(AnsiString(
          X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx)))));
  finally
    if store_ctx <> nil then X509_STORE_CTX_free(store_ctx);
    if store     <> nil then X509_STORE_free(store);
    if cert      <> nil then X509_free(cert);
  end;
end;

end.
