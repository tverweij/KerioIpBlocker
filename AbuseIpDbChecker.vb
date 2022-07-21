Imports System.Net
Imports Microsoft.VisualBasic

Public Class AbuseIpDbChecker
  Implements BlackListInterface

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
  //                 the cache is still working, but new IP's are all allowed if they    //
  //                                               were not blocked in the past          //
  //                                                                                     //
  /////////////////////////////////////////////////////////////////////////////////////////

  //Interface /////////////////////////////////////////////////////////////////////////////

  Public Property API_Key As String Implements BlackListInterface.API_Key

  //checks if the IP is Ok or not
  Public Function CheckIP(IP As String) As Boolean Implements BlackListInterface.CheckIP
    If  ExistsInCache(IP) Then
      Return Cache(IP)
    Else
      //check online
      Try
        Dim IpOk = IsIpOk(IP)
        If Cache.ContainsKey(IP) Then
          Cache(IP) = IpOk
          Cache_TTL(IP) = Now
        Else
          Cache.Add(IP, IpOk)
          Cache_TTL.Add(IP, Now)
        End If
        //update the lookup file
        My.Computer.FileSystem.WriteAllText(LookupFile, IP & "|" & IpOk.ToString & "|" & Now.ToString & Chr(10), True)
        Return Cache(IP)

      Catch ex As Exception
        //failed to get the online information (out of request)
        //check the cache again for old entries, without looking for the TTL
        If Cache.ContainsKey(IP) Then
          Return Cache(IP)
        Else
          //It's not in the cache, means we can not check, so just allow
          Return True
        End If
      End Try
    End If
  End Function

  Private BlackListRead As Boolean = False
  //get the (max) 10.000 most misused IP's to fill the cache (100.000 for Basic and 500.000 for premium) - only IP addresses that are 100% certain misused.
  Public Sub ReadBlacklist Implements BlackListInterface.ReadBlacklist
    Dim BlackList As String
    Try
      Dim ReReadBlackList = Not System.IO.file.Exists(BlackListFile)
      If Not ReReadBlackList Then
        ReReadBlackList = DateDiff(DateInterval.Hour, System.IO.File.GetLastWriteTime(BlackListFile), Now) > 12
      End If
      If ReReadBlackList Then
        BlackListRead = False
        Dim myReq As HttpWebRequest = DirectCast(HttpWebRequest.Create("https://api.abuseipdb.com/api/v2/blacklist"), HttpWebRequest)
        myReq.Method = "GET"
        myReq.Headers.Add("Key", API_Key)
        myReq.Accept = "text/plain"

        Dim myResp = myReq.GetResponse
        Dim myReader = New System.IO.StreamReader(myResp.GetResponseStream)

        BlackList = myReader.ReadToEnd
        //save the blacklist for re-use
        My.Computer.FileSystem.WriteAllText(BlackListFile, BlackList, False)
      Else
        //read the saved cache
        BlackList = My.Computer.FileSystem.ReadAllText(BlackListFile)
      End If

    Catch
      //we can not load the blacklist online (too many requests or connection problem) - load and reuse the last saved blacklist
      BlackList = My.Computer.FileSystem.ReadAllText(BlackListFile)
    End Try

    //Load the downloaded blacklist in the cache
    If Not BlackListRead Then
      For Each IP As String  In Split(BlackList, Chr(10))
        If Not ExistsInCache(IP) Then
          Cache.Add(IP, False)
          Cache_TTL.Add(IP, Now)
        Else
          Cache_TTL(IP) = Now //update the TTL
        End If
      Next
      BlackListRead = True
    End If
  End Sub

  //Reload the last used cache
  Public Sub ReadLookupCache Implements BlackListInterface.ReadLookupCache
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

          If Not ExistsInCache(IP) Then
            Cache.Add(IP, IpOk)
            Cache_TTL.Add(IP, TTL)
            NewLookupFile.Append(IP & "|" & IpOk.ToString & "|" & TTL_String & Chr(10))
          End If
        End If
      Next
      //write the file again, but only with the entries that are still valid
      My.Computer.FileSystem.WriteAllText(LookupFile, NewLookupFile.ToString, false)
    End If
  End Sub

  //Report an abuse IP with the ports it tried to open
  Public Sub ReportIP(ip As String, ports As String) Implements BlackListInterface.ReportIP
    Dim Reason As String
    Dim categories As string
    Dim Checker = "," & ports & ","
    If (Checker).Contains(",20,") OrElse
       (Checker).Contains(",22,") OrElse
       (Checker).Contains(",23,") OrElse
       (Checker).Contains(",69,") OrElse
       (Checker).Contains(",88,") OrElse
       (Checker).Contains(",161,") OrElse
       (Checker).Contains(",445,") OrElse
       (Checker).Contains(",464,") OrElse
       (Checker).Contains(",465,") OrElse
       (Checker).Contains(",500,") OrElse
       (Checker).Contains(",587,") OrElse
       (Checker).Contains(",749,") OrElse
       (Checker).Contains(",750,") OrElse
       (Checker).Contains(",8080,") Orelse
       (Checker).Contains(",1433,") Orelse
       (Checker).Contains(",3389,") Then
      categories = "15" //hacking
    Else
      categories = "14" //portscan
    End If
    If ("," & ports & ",").Contains(",22,") Then
      categories &= ",22" //ssh
    End If
    
    //sort the ports and add a space after the comma for displaying purposes
    Dim prt As New System.Collections.Generic.List(Of string)
    prt.AddRange(Split(ports,","))
    prt.sort
    ports = Join(prt.ToArray, ", ")
    If ports.IndexOf(",") = -1 Then
      Reason = "Tried to connect to port " & ports
    Else
      Reason = "Tried to connect to ports " & ports
    End If
    
    Reason = Reason.Replace(",", ", ") //layout for display on website
    Dim myReq As HttpWebRequest = DirectCast(HttpWebRequest.Create($"https://api.abuseipdb.com/api/v2/report?ip={ip}&comment={Reason}&categories={categories}"), HttpWebRequest)
    myReq.Method = "POST"
    myReq.Headers.Add("Key", API_Key)
    myReq.Accept = "text/plain"

    Dim myResp = myReq.GetResponse
    Dim myReader = New System.IO.StreamReader(myResp.GetResponseStream)

    //{"data":{"ipAddress":"118.193.21.186","abuseConfidenceScore":100}}
    Dim ResponseData = myReader.ReadToEnd

    //Add to cache (response data tells us the current abuse score, so we can use that info, saving another online lookup)
    Dim IpOK As Boolean = Not ResponseData.Contains("""abuseConfidenceScore"":100")
    Dim TTL = Now
    If Not ExistsInCache(ip) Then
      Cache.Add(ip, IpOK)
      Cache_TTL.Add(ip, TTL)
    Else
      Cache(ip) = IpOK
      Cache_TTL(ip) = TTL
    End If
    //persist this entry
    My.Computer.FileSystem.WriteAllText(LookupFile, ip & "|" & IpOK.ToString & "|" & TTL.ToString & Chr(10), True)
  End Sub

  /////////////////////////////////////////////////////////////////////////////////////////

  // Implementation ///////////////////////////////////////////////////////////////////////

  Private BlackListFile As String = Environ("APPDATA") & "\AbuseIPDB_BackListCache.txt"
  Private LookupFile As String = Environ("APPDATA") & "\AbuseIPDB_LookupCache.txt"

  Private Cache As New RemObjects.Elements.RTL.Dictionary(Of String, Boolean)
  Private Cache_TTL As New RemObjects.Elements.RTL.Dictionary(Of String, DateTime)
  Private UseTTL As Integer = 24 //cache is valid for 24 hours

  //Check if the requested IP is in the cache - if it's in and older than the UseTTL value in hours, the IP is reported as not being in the cache
  Private Function ExistsInCache(IP As String) As Boolean
    If Cache_TTL.ContainsKey(IP) Then
      If DateAdd(DateInterval.Hour, UseTTL, Cache_TTL(IP)) < DateTime.Now Then
          //entry is not valid anymore
          Return False
      Else
        Return True
      End If
    Else
      Return False
    End If
  End Function

  //Check the requested IP online
  Private Function IsIpOk(Ip As String) As Boolean
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
    Return Val(Score) < 100
  End Function

End Class
