Imports System.IO
Imports System.Diagnostics
Imports System.Collections
Imports System.Collections.Generic
Imports Microsoft.VisualBasic

Module Program

  // parameters: -P:AdminPpassword -M:MaxCountOfBlockedAddresses -A:APIKeyForAbuseDB
  Sub Main(args as String())

    //accept all certificates on the SSL connection to the firewall
    System.Net.ServicePointManager.ServerCertificateValidationCallback =
            Function(se As Object, cert As System.Security.Cryptography.X509Certificates.X509Certificate,
                     chain As System.Security.Cryptography.X509Certificates.X509Chain, sslerror As System.Net.Security.SslPolicyErrors)
                Return True
            End Function

    //read the arguments
    For Each a As String In args
      If a.StartsWith("-P:") Then
        AdminPassword = a.Substring(3).trim
      End If
      If a.StartsWith("-M:") Then
        MaxCountOfBlockedAddresses = CInt(Val(a.Substring(3).trim))
      End If
      If a.StartsWith("-A:") Then
        API_Key = a.Substring(3).trim
      End If
    Next

    //read the previous done lookups to minimize the amount of needed online lookups
    ReadLookupCache
    //cache the blacklist, minimum of 10.000 addresses
    ReadBlacklist

    //main loop
    do
      try
        Login
        UpdateBlocked(GetIpToBlockFromConnectionLog(GetConnectionLog))
        Logout
      Catch
      End try
      threading.Thread.Sleep(15000) 'sleep 15 seconds

      //read the updated blacklist every 12 hours, update the cache and the TTL for these addresses
      ReadBlacklist
    Loop
  End Sub

  Public Function GetIpToBlockFromConnectionLog(MyLog As String) As RemObjects.Elements.RTL.List(Of String)
    Dim ReturnValue As New RemObjects.Elements.RTL.List(Of String)

    //split the log in an array of lines
    Dim TheLog = Split(MyLog, Chr(13)+Chr(10))
    Array.Reverse(TheLog)

    //loop the lines
    For Each line As String In TheLog With Index i
      //only the last 150 lines
      If i = 150 Then
        Exit for
      End If

      If line.Contains("[Connection]") Then
        Dim OriginIP = ParseOriginIP(line)
        If Not CheckIP(OriginIP) Then

          //This IP is listed In AbuseIP DB -> Add to the IP Adresses to block
          ReturnValue.Add(OriginIP)
        End If
        Dim DestIP = ParseDestinationIP(line)
        If Not CheckIP(DestIP) Then

          //This IP is listed In AbuseIP DB -> Add to the IP Adresses to block
          ReturnValue.Add(DestIP)
        End If
      End if
    Next
    Return ReturnValue
  End Function

    //Line layout:
    //[<DateTime>] [ID] <LogIDnumber> [Rule] <RuleName> [Service] <ServiceConnectedTo> [Connection] <UDP/TCP> <RemoteNameOrIP_WhenName:(IP)>:<RemotePort> -> <LocalNameOrIP_WhenName:(IP)>:<LocalPort> [Iface] <NetworkInterfaceName> [Duration] <ConnectionDuration> sec [Bytes] <BytesTransferred> [Packets] <PacketsTransferred>

  Private Function ParseOriginIP(logLine As String) As String
    //Get the Origin IP Address
    Return _ParseIp(Split(logLine, "[Connection]")(1).Substring(5))
  End Function

  Private Function ParseDestinationIP(logLine As String) As String
    //Get the Destination IP Address
    Return  _ParseIp(Split(logLine, " -> ")(1))
  End Function

  Private Function _ParseIp(IpDescription As String) As String
    Dim Ip As String
    If IpDescription.Contains(":") Then
      Ip = Split(IpDescription, ":")(0)
      If Ip.Contains("(") Then
        Ip = Split(Ip, "(")(1)
        Ip = Split(Ip, ")")(0)
      End If
    ElseIf IpDescription.Contains(" -> ") Then
      Ip = Split(IpDescription, " -> ")(0)
      If Ip.Contains("(") Then
        Ip = Split(Ip, "(")(1)
        Ip = Split(Ip, ")")(0)
      End If
    Else
      Ip = Split(IpDescription, " [")(0)
      If Ip.Contains("(") Then
        Ip = Split(Ip, "(")(1)
        Ip = Split(Ip, ")")(0)
      End If
    End If
    Return Ip
  End Function

  Property MaxCountOfBlockedAddresses As Integer

  Public Sub UpdateBlocked(IpsToBlock As RemObjects.Elements.RTL.List(Of String))
   'Get the current groups
    Dim List = GetIPAddressGroups
    Dim GroupId As String = "AbuseIpDBBlock" //default group Id when the group does not exist

    Dim Blocked As New SortedDictionary(Of DateTime, String)

    For Each l As String In List
      If l.Contains("""groupName"":""AbuseIP DB Blocked""") Then
        //this is a line of the group with the blocked IP Addresses

        //get the IP, description and ID of this line
        Dim Id = l.Substring(l.IndexOf("""id"":")+5)
        Id = Id.Substring(0, Id.IndexOf(","))
        Dim Ip = l.Substring(l.IndexOf("""host"":")+8)
        Ip = Ip.Substring(0, Ip.IndexOf(""","))
        Dim Desc = l.Substring(l.IndexOf("""description"":")+15)
        Desc = Desc.Substring(0, Desc.IndexOf(""","))

        //Get the correct group id
        GroupId = l.Substring(l.IndexOf("""groupId"":")+11)
        GroupId = GroupId.Substring(0, GroupId.IndexOf(""","))

        If Desc <> "PlaceHolder" Then
          //get the TTL from the desciption
          Dim TTL As Date
          Try
            TTL = Microsoft.VisualBasic.DateAndTime.DateAdd(Microsoft.VisualBasic.DateInterval.Day, 1, DateTime.Parse(Desc))
          Catch
            TTL = New Date //not a valid date time in the description - so we remove the entry
          End Try

          If TTL < Now Then
            //entry is not valid anymore
            RemoveIPEntry(Id)
          Else
            //still valid, so this one is blocked
            //prevent duplicated keys in the dictionary
            Do While Blocked.ContainsKey(TTL)
              TTL = Microsoft.VisualBasic.DateAndTime.DateAdd(Microsoft.VisualBasic.DateInterval.Second, 1, TTL)
            Loop

            Blocked.Add(TTL, Id)
          End If

          If IpsToBlock.Contains(Ip) Then
            //it is already there, so remove it from the list
            IpsToBlock.Remove(Ip)
          End If
        End If
      End If
    Next

    For Each IpEntry As String In IpsToBlock
      //create the new entry
      AddIPEntry(GroupId, "AbuseIP DB Blocked", IpEntry)
      Blocked.Add(Now, "-1")
    Next


    Dim TotalBlocked = Blocked.Count
    For Each dt As DateTime In Blocked.Keys
      If TotalBlocked > MaxCountOfBlockedAddresses Then
        If Blocked(dt) <> "-1" Then
          RemoveIPEntry(Blocked(dt))
          TotalBlocked -= 1
        End If
      Else
        Exit For
      End If
    Next

    //Apply the changes
    ApplyIPChanges
  End Sub


End Module