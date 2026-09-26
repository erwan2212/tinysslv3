unit userverhttps;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Sockets, Classes, Crt,
  openssl_types, openssl_ssl;

const
  DEFAULT_PORT = 8443;

// Procédures publiques pour contrôler le serveur depuis une autre unité
procedure StartHttpsServer(APort: Word = DEFAULT_PORT);
procedure StopHttpsServer;
function IsHttpsServerRunning: Boolean;

implementation

var
  ServerSock: LongInt = -1;
  Running: Boolean = False;
  Ctx: PSSL_CTX = nil;
  ServerThread: TThread = nil;
  CurrentPort: Word = DEFAULT_PORT;

type
  TServerThread = class(TThread)
  protected
    procedure Execute; override;
  end;

procedure TServerThread.Execute;
var
  ClientSock: LongInt;
  Addr: TInetSockAddr;
  ClientAddr: TInetSockAddr;
  ClientLen: TSockLen;
  OptVal: LongInt;
  Ssl: PSSL;
  ReadBuf: array[0..1023] of AnsiChar;
  BytesRead: Integer;
  Response: AnsiString;
begin
  Ctx := SSL_CTX_new(TLS_server_method);
  if Ctx = nil then
  begin
    Writeln('Erreur: Impossible de créer le contexte SSL.');
    Exit;
  end;

  try
    if SSL_CTX_use_certificate_file(Ctx, 'server.crt', SSL_FILETYPE_PEM) <= 0 then
    begin
      Writeln('Erreur: Impossible de charger server.crt');
      Exit;
    end;

    if SSL_CTX_use_PrivateKey_file(Ctx, 'server.key', SSL_FILETYPE_PEM) <= 0 then
    begin
      Writeln('Erreur: Impossible de charger server.key');
      Exit;
    end;

    ServerSock := fpsocket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if ServerSock < 0 then Exit;

    OptVal := 1;
    fpsetsockopt(ServerSock, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));

    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(CurrentPort);
    Addr.sin_addr.s_addr := htonl(INADDR_ANY);

    if fpbind(ServerSock, @Addr, SizeOf(Addr)) < 0 then
    begin
      CloseSocket(ServerSock);
      Exit;
    end;

    if fplisten(ServerSock, 5) < 0 then
    begin
      CloseSocket(ServerSock);
      Exit;
    end;

    Writeln('==================================================');
    Writeln(' Serveur HTTPS en écoute sur https://localhost:', CurrentPort);
    Writeln(' Appuyez sur [ESC] pour arrêter le serveur.');
    Writeln('==================================================');

    while Running do
    begin
      ClientLen := SizeOf(ClientAddr);
      ClientSock := fpaccept(ServerSock, @ClientAddr, @ClientLen);

      if not Running or (ClientSock < 0) then Break;

      Ssl := SSL_new(Ctx);
      SSL_set_fd(Ssl, ClientSock);

      if SSL_accept(Ssl) <= 0 then
      begin
        Writeln('Erreur lors du handshake TLS (SSL_accept)');
      end
      else
      begin
        FillChar(ReadBuf, SizeOf(ReadBuf), 0);
        BytesRead := SSL_read(Ssl, @ReadBuf, SizeOf(ReadBuf) - 1);
        if BytesRead > 0 then
        begin
          Writeln('[Requête HTTP reçue]');
        end;

        Response := 'HTTP/1.1 200 OK'#13#10 +
                    'Content-Type: text/html; charset=UTF-8'#13#10#13#10 +
                    '<html><body><h1>Hello depuis TinySSL / FPC HTTPS !</h1></body></html>';

        SSL_write(Ssl, PAnsiChar(Response), Length(Response));
      end;

      SSL_shutdown(Ssl);
      SSL_free(Ssl);
      CloseSocket(ClientSock);
    end;

  finally
    if ServerSock >= 0 then
    begin
      CloseSocket(ServerSock);
      ServerSock := -1;
    end;
    if Ctx <> nil then
    begin
      SSL_CTX_free(Ctx);
      Ctx := nil;
    end;
  end;
end;

procedure StartHttpsServer(APort: Word);
begin
  if Running then Exit;

  CurrentPort := APort;
  Running := True;
  ServerThread := TServerThread.Create(False); // Démarre le thread
end;

procedure StopHttpsServer;
begin
  if not Running then Exit;

  Running := False;
  // Ferme brutalement le socket d'écoute pour débloquer immédiatement fpaccept
  if ServerSock >= 0 then CloseSocket(ServerSock);

  if Assigned(ServerThread) then
  begin
    ServerThread.WaitFor;
    ServerThread.Free;
    ServerThread := nil;
  end;
  Writeln('Serveur HTTPS arrêté.');
end;

function IsHttpsServerRunning: Boolean;
begin
  Result := Running;
end;

initialization

finalization
  // Sécurité : s'assure que le serveur s'arrête si l'application se ferme
  StopHttpsServer;

end.
