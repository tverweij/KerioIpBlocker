Imports System.Net
Imports Microsoft.VisualBasic

Public Module AbuseDbChecker
  /////////////////////////////////////////////////////////////////////////////////////////
  //                                                                                     //
  // Implementation of the AbuseDb IP Checker                                            //
  //-------------------------------------------------------------------------------------//
  //                                                                                     //
  // Every IP Address in the Connection log of Kerio is checked agains this DB           //
  // When an IP address is found here, it is blocked for the next 24 hours               //
  //                                                                                     //
  // You need to register an API key to use this code, see:                              //
  // https://www.abuseipdb.com/pricing                                                   //
  //                                                                                     //
  // This code works with all plans, but with a higher plan more IP's are cached         //
  //                                                                                     //
  //   Individual plan: 10.000 IP's cached at startup + max 1.000 extra checks a day     //
  //   Basic plan:    max 100.000 IP's cached at startup + max 10.000 extra checks a day //
  //   Premium plan:  max 500.000 IP's cached at startup + max 50.000 extra checks a day //
  //                                                                                     //
  // At the moment you are out of checks:                                                //
  //                 the cache is still working, but new IP's are all allowed            //
  //                                                                                     //
  /////////////////////////////////////////////////////////////////////////////////////////

  Public Property API_Key As String

  //IP Cache
  Private Cache As New RemObjects.Elements.RTL.Dictionary(Of String, Boolean)
  Private Cache_TTL As New RemObjects.Elements.RTL.Dictionary(Of String, DateTime)
  Private UseTTL As Integer = 24 //cache is valid for 24 hours

  Private BlackListFile As String = Environ("APPDATA") & "\AbuseIPDB_BackListCache.txt"
  Private LookupFile As String = Environ("APPDATA") & "\AbuseIPDB_LookupCache.txt"

  Private Function ExistsInCache(IP As String) As Boolean
    If Cache_TTL.ContainsKey(IP) Then
      If DateAdd(DateInterval.Hour, UseTTL, Cache_TTL(IP)) < DateTime.Now Then
        //entry is not valid anymore -> remove the entry
        Cache_TTL.Remove(IP)
        Cache.Remove(IP)
        Return False
      Else
        Return True
      End If
    Else
      Return False
    End If
  End Function

  Public Function CheckIP(IP As String) As Boolean
    If Not ExistsInCache(IP) Then
      //check online
      Try
        Dim IpOk = IsIpOk(IP)
        Cache.Add(IP, IpOk < 100)
        Cache_TTL.Add(IP, Now)
        //update the lookup file
        My.Computer.FileSystem.WriteAllText(LookupFile, IP & "|" & IpOk.ToString & "|" & Now.ToString & Chr(10), True)
      Catch ex As Exception
        RemObjects.Elements.RTL.writeLn("IP Lookup error: " & ex.Message)
        Return True
      End Try
    End If
    Return Cache(IP)
  End Function

  Public Function IsIpOk(Ip As String) As Integer
    Try
      Dim myReq As HttpWebRequest = DirectCast(HttpWebRequest.Create($"https://api.abuseipdb.com/api/v2/check?ipAddress={Ip}"), HttpWebRequest)
      myReq.Method = "GET"
      myReq.Headers.Add("Key", API_Key)
      myReq.Accept = "text/plain"

      //myReq.GetRequestStream.Write(System.Text.Encoding.UTF8.GetBytes(JsonData), 0, System.Text.Encoding.UTF8.GetBytes(JsonData).Length)
      Dim myResp = myReq.GetResponse
      Dim myReader = New System.IO.StreamReader(myResp.GetResponseStream)
      Dim ReturnValue As String = myReader.ReadToEnd

      //{"data":{"ipAddress":"193.201.9.89","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":100,"countryCode":"RU","usageType":"Data Center\/Web Hosting\/Transit","isp":"Infolink LLC","domain":"informlink.ru","hostnames":[],"totalReports":211,"numDistinctUsers":41,"lastReportedAt":"2022-07-07T13:00:02+00:00"}}
      Dim Score As String = Split(ReturnValue, """abuseConfidenceScore"":")(1)
      Score = Split(Score, ",")(0)
      Return CInt(Val(Score))
    Catch ex As Exception
      System.Diagnostics.Debug.Print("Error: " & ex.Message)
      Throw ex
    End Try
  End Function

  //get the (max) 10.000 most misused IP's to fill the cache (100.000 for Basic and 500.000 for premium) - only IP addresses that are 100% certain misused.
  Public Sub ReadBlacklist
    Dim BlackList As String
    Try
      Dim ReReadBlackList = Not System.IO.file.Exists(BlackListFile)
      If Not ReReadBlackList Then
        ReReadBlackList = DateDiff(DateInterval.Hour, System.IO.File.GetLastWriteTime(BlackListFile), Now) > 12
      End If
      If ReReadBlackList Then
        Dim myReq As HttpWebRequest = DirectCast(HttpWebRequest.Create("https://api.abuseipdb.com/api/v2/blacklist"), HttpWebRequest)
        myReq.Method = "GET"
        myReq.Headers.Add("Key", API_Key)
        myReq.Accept = "text/plain"

        Dim myResp = myReq.GetResponse
        Dim myReader = New System.IO.StreamReader(myResp.GetResponseStream)

        BlackList = myReader.ReadToEnd
        //save the blacklist for re-use
        My.Computer.FileSystem.WriteAllText(BlackListFile, BlackList, False)
      End If
    Catch ex As Exception
      //we load the last saved blacklist
      BlackList = My.Computer.FileSystem.ReadAllText(BlackListFile)
    End Try

    //Load the blacklist in the cache
    For Each IP As String  In Split(BlackList, Chr(10))
      If Not ExistsInCache(IP) Then
        Cache.Add(IP, False)
        Cache_TTL.Add(IP, Now)
      Else
        Cache_TTL(IP) = Now //update the TTL
      End If
    Next
  End Sub

  Public Sub ReadLookupCache
    If System.IO.file.Exists(LookupFile) Then
      Dim Lookup As String = My.Computer.FileSystem.ReadAllText(LookupFile)
      Dim NewLookupFile As New RemObjects.Elements.RTL.StringBuilder

      //Load the existing (and still valid) lookups in the cache
      Dim ToIterate = Split(Lookup, Chr(10))
      Array.Reverse(ToIterate)
      For Each IP_TTL As String  In ToIterate //latest lookups read first
        If IP_TTL.Length > 0 Then
          Dim IP = Split(IP_TTL, "|")(0)
          Dim IpOk = CBool(Split(IP_TTL, "|")(1))
          Dim TTL_String = Split(IP_TTL, "|")(2)
          Dim TTL = CDate(TTL_String)
          If DateAdd(DateInterval.Hour, 24, TTL) > Now Then
            //still valid
            If Not ExistsInCache(IP) Then
              Cache.Add(IP, IpOk)
              Cache_TTL.Add(IP, TTL)
            End If
            NewLookupFile.Append(IP & "|" & IpOk.ToString & "|" & TTL_String & Chr(10))
          End If
        End If
      Next
      //write the file again, but only with the still valid entries
      My.Computer.FileSystem.WriteAllText(LookupFile, NewLookupFile.ToString, false)
    End If
  End Sub


End Module
