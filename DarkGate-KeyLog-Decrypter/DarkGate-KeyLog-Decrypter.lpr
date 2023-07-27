{ Author: Zachary Reichert, Stroz Friedberg. This program reads the current directory for any .log files, if found - it will attempt to read the file and decrypt its contents. The output is saved to "Decrypted_<original file name>.txt"}

program project1;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Types, Classes, SysUtils, CustApp, DCPCrypt2, DCPsha1, DCPblockciphers, DCPrijndael;

type


  TMyApplication = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  end;


procedure ProcessLogFile(const Key, FileName: string);
var
  EncryptedString, DecryptedString: string;
  FileContent: TStringList;
  InputFile, OutputFile: TextFile;
  OutputFileName: string;
  Cipher: TDCP_rijndael;         // the cipher to use
  Hash: TDCP_hashclass;             // the hash to use
begin
	// Try and read file
	FileContent := TStringList.Create;
		try
		  FileContent.LoadFromFile(FileName);
		  EncryptedString := FileContent.Text;
		finally
		  FileContent.Free;
		end;
	// Decrypt the base64 encoded contents of the file
	Cipher :=  TDCP_rijndael.Create(nil);
	Cipher.InitStr(Key, TDCP_sha1);
	DecryptedString := Cipher.DecryptString(EncryptedString);


	// Prepare the output file name
	OutputFileName := ExtractFilePath(FileName) + 'Decrypted_' + ExtractFileName(FileName) + '.txt';

	// Write decrypted string to output file
	AssignFile(InputFile, FileName);
	AssignFile(OutputFile, OutputFileName);
	Reset(InputFile);
	Rewrite(OutputFile);
	while not Eof(InputFile) do
	begin
	  Readln(InputFile, EncryptedString);
	  Writeln(OutputFile, DecryptedString);
	end;
	CloseFile(InputFile);
	CloseFile(OutputFile);

	// Output success message
	Writeln('Decrypted file created: ' + OutputFileName);

end;

procedure TMyApplication.DoRun;
var
  ErrorMsg: String;
  EncryptedString, KeyStr, FileName, DecryptedString: string;
  Cipher: TDCP_rijndael;         // the cipher to use
  Hash: TDCP_hashclass;             // the hash to use
  FileContent: TStringList;
  OutputFile: TextFile;
  SearchRec: TSearchRec;

begin
	  // quick check parameters
	  ErrorMsg:=CheckOptions('h', 'help');
	  if ErrorMsg<>'' then begin
		ShowException(Exception.Create(ErrorMsg));
		Terminate;
		Exit;
	  end;

	  // parse parameters
	  if HasOption('h', 'help') then begin
		WriteHelp;
		Terminate;
		Exit;
	  end;

	begin
		// Set the encrypted string and key
		KeyStr := 'masteroflog';

		// Search for log files in the current directory
		if FindFirst('*.log', faAnyFile, SearchRec) = 0 then
		begin
		  repeat
			// Process each log file
			FileName := ExtractFilePath(ParamStr(0)) + SearchRec.Name;
			ProcessLogFile(KeyStr, FileName);
		  until FindNext(SearchRec) <> 0;
		  FindClose(SearchRec);
		end;

		Writeln('Press any key to exit...');
		Readln;

	  end;
	Terminate;
end;

constructor TMyApplication.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
end;

destructor TMyApplication.Destroy;
begin
  inherited Destroy;
end;

procedure TMyApplication.WriteHelp;
begin
  writeln('Usage: ', ExeName, ' -h');
  writeln('This Program looks in the current directory for any files with the extension of ".log" if it finds any, it will decrypt their contents using CFB8bit mode via DecryptString in DCPCrypt library.');
end;

var
  Application: TMyApplication;
begin
  Application:=TMyApplication.Create(nil);
  Application.Title:='DarkGate Keylog Decryptor';
  Application.Run;
  Application.Free;
end.
