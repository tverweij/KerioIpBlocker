Imports System.Net
Imports System.Net.NetworkInformation
Imports System.Linq
Imports Microsoft.VisualBasic

Public Class KerioFirewall
  Implements FirewallInterface

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                                                                                               //
  // Firewall communication - we assume that the firewall is the gateway of this machine                           //
  //                                                                                                               //
  // The only implemented parts are needed for the KerioIPBlocker                                                  //
  //                                                                                                               //
  // More API information, see:                                                                                    //
  // https://www.gfi.com/products-and-solutions/network-security-solutions/kerio-control/resources/developer-zone  //                                                                                 //
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  Public Property AdminPassword As String

  // initialization ///////////////////////////////////////////////////////////////////////

  //The kerio control instance is located on the gateway of the network connection
  Private Ip = GetGateWay.ToString
  Private URL = "https://" & Ip & ":4081/admin/api/jsonrpc"

  //cookies for the connection
  Private Cookie As String = Null
  Dim Cookie1 As Cookie
  Dim Cookie2 As Cookie

  Private Function GetGateWay() As IPAddress
     //we do a traceroute to the first IP - this is the current active gateway
    Dim pinger As Ping = New Ping
    Dim pingerOptions As PingOptions = New PingOptions(1, True) //return the first hop only
    Dim timeout As Integer = 10000 //we use a 10 second time-out
    Dim buffer() As Byte = Encoding.ASCII.GetBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    Dim reply As PingReply

    reply = pinger.Send("8.8.8.8", timeout, buffer, pingerOptions)

    If {IPStatus.Success, IPStatus.TtlExpired}.Contains(reply.Status) Then
      Return reply.Address
    Else
      Throw New RemObjects.Elements.RTL.InvalidOperationException("Gateway not found")
    End If
  End Function

  /////////////////////////////////////////////////////////////////////////////////////////


  // public methods ///////////////////////////////////////////////////////////////////////

  //Login in to the firewall as Admin
  Public Sub Login Implements FirewallInterface.Login
    Dim Result = CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.login"",""params"":{""userName"":""admin"",""password"":""" & AdminPassword & """,""application"":{""name"":""KerioIPBlocker"",""vendor"":""buildIT IT-Solutions BV"",""version"":""1.0""}}}")
    Result = Result.Substring(Result.IndexOf("""token"":")+9)
    Cookie = Result.Substring(0, Result.Length - 3)
  End Sub

  //Logout from the firewall
  Public Sub Logout Implements FirewallInterface.Logout
    //confirm change
    Dim time = CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.getConfigTimestamp""}")
    time = time.Substring(time.IndexOf("""timestamp"":")+12)
    time = time.Substring(0, time.IndexOf("}"))
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.confirmConfig"",""params"":{""clientTimestampList"":[{""name"":""config"",""timestamp"":" & time & "}]}}")

    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.logout"", ""params"":{}}")
    Cookie = Null
  End Sub

  //Get the IP Addresses and descriptions in a group
  Public Function GetIPAddressGroup(GroupName As String) As RemObjects.Elements.RTL.List(Of GroupEntry) Implements FirewallInterface.GetIPAddressGroup
    Dim ReturnValue As New RemObjects.Elements.RTL.List(Of GroupEntry)

    For Each l As String In Split(CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.get"",""params"":{""query"":{""orderby"":[{""columnName"":""groupId"", ""direction"":""Asc""}]}}}"), "},{")
      If l.Contains($"""groupName"":""{GroupName}""") Then
        //this is a line of the specified group

        //get the IP, description and ID of this line
        Dim Id = l.Substring(l.IndexOf("""id"":")+5)
        Id = Id.Substring(0, Id.IndexOf(","))
        Dim Ip = l.Substring(l.IndexOf("""host"":")+8)
        Ip = Ip.Substring(0, Ip.IndexOf(""","))
        Dim Desc = l.Substring(l.IndexOf("""description"":")+15)
        Desc = Desc.Substring(0, Desc.IndexOf(""","))

        //Get the correct group id
        Dim GroupId = l.Substring(l.IndexOf("""groupId"":")+11)
        GroupId = GroupId.Substring(0, GroupId.IndexOf(""","))

        Dim grp As New GroupEntry
        With grp
          .Group = New Group With {.Id = GroupId, .Name = GroupName}

          .ID = Id
          .IP = Ip
          .Desc = Desc
        End With
        ReturnValue.Add(grp)
      End If
    Next
    Return ReturnValue
  End Function

  //Remove an entry from the IP Address Groups
  Public Sub RemoveIPEntry(entry As GroupEntry) Implements FirewallInterface.RemoveIPEntry
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.remove"",""params"":{""groupIds"":[" & entry.ID & "]}}")
  End Sub

  //Add a hos entry to the IP Address Groups
  Public Sub AddIPEntry(entry As GroupEntry) Implements FirewallInterface.AddIPEntry
    Dim Description = Date.Now.ToString
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.create"",""params"":{""groups"":[{""groupId"": """ & entry.Group.Id & """,""groupName"":""" & entry.Group.Name & """,""enabled"":true,""description"":""" & entry.Desc & """,""host"":""" & entry.IP & """,""Type"":""Host""}]}}")
  End Sub

  //Apply IP Group changes
  Public Sub ApplyIPChanges Implements FirewallInterface.ApplyIPChanges
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.apply""}")
  End Sub

  Public Function GetConnectionIPAdresses As RemObjects.Elements.RTL.List(Of String) Implements FirewallInterface.GetConnectionIPAdresses
    Dim ReturnValue As New RemObjects.Elements.RTL.List(Of String)
    Dim TheLog = Split(GetLog("connection"), Chr(13)+Chr(10))

    Array.Reverse(TheLog)

    //loop the lines
    For Each line As String In TheLog With Index i
      //only the last 150 lines
      If i = 150 Then
        Exit for
      End If

      If line.Contains("[Connection]") Then
        Dim OriginIP = ParseOriginIP(line)
        If Not ReturnValue.Contains(OriginIP) Then
          ReturnValue.Add(OriginIP)
        End If
        Dim DestIP = ParseDestinationIP(line)
        If Not ReturnValue.Contains(DestIP) Then
          ReturnValue.Add(DestIP)
        End If
      End if
    Next
    Return ReturnValue
  End Function

  Public Function GetFilterLog As String
    Return GetLog("filter")
  End Function

  /////////////////////////////////////////////////////////////////////////////////////////

  // implementation ///////////////////////////////////////////////////////////////////////

  Private FromLine As New System.Collections.Generic.Dictionary(Of String, Integer)
  Private Function GetLog(whatLog As String) As String
    Dim myReq As HttpWebRequest
    If Not FromLine.ContainsKey(whatLog) Then
      FromLine.Add(whatLog, 0)
    End If
    For i As Integer = 0 To 1
      //This RPC call returns a download link
      Dim Result = CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Logs.exportLog"",""params"":{""logName"":""" & whatLog & """,""fromLine"":" & FromLine(whatLog).ToString & ",""countLines"":-1,""type"":""PlainText""}}")
      Result = Result.Substring(Result.IndexOf("""url"":")+7)
      Dim download = Result.Substring(0, Result.IndexOf(""""))

      //download the log
      Try
        myReq = DirectCast(HttpWebRequest.Create(download), HttpWebRequest)
        Exit For
      Catch
        //Log has been cleared
        FromLine(whatLog) = 0
      End Try
    Next
    myReq.Method = "Get"
    myReq.Headers.Add("X-Token", Cookie)
    myReq.CookieContainer = New CookieContainer
    Dim c = New CookieCollection
    c.Add(Cookie1)
    c.Add(Cookie2)
    myReq.CookieContainer.Add(c)
    Dim myResp = myReq.GetResponse
    Dim myReader = New System.IO.StreamReader(myResp.GetResponseStream)
    Dim ReturnValue As String = myReader.ReadToEnd

    FromLine(whatLog) += Split(ReturnValue, Chr(13) & Chr(10)).Length - 1
    Return ReturnValue
  End Function

  //Do an RPC call to the firewall
  Private Function CallRpc(JsonData As String) As String
    Try
      Dim myReq As HttpWebRequest = DirectCast(HttpWebRequest.Create(URL), HttpWebRequest)
      myReq.Method = "POST"
      myReq.ContentType = "application/json-rpc; charset=UTF-8"
      myReq.Accept = "application/json-rpc"
      If Cookie IsNot Null then
        myReq.Headers.Add("X-Token", Cookie)
        myReq.CookieContainer = New CookieContainer
        Dim c = New CookieCollection
        c.Add(Cookie1)
        c.Add(Cookie2)
        myReq.CookieContainer.Add(c)
      End If

      myReq.GetRequestStream.Write(System.Text.Encoding.UTF8.GetBytes(JsonData), 0, System.Text.Encoding.UTF8.GetBytes(JsonData).Length)
      Dim myResp = myReq.GetResponse
      For Each x As String In myResp.Headers.AllKeys
        If x = "Set-Cookie" Then
          Dim MyCookies = Split(myResp.Headers(x),"HttpOnly,")

          Dim MyCookie1 = Split(MyCookies(0), ";")
          Cookie1 = New Cookie(Split(MyCookie1(0), "=")(0), Split(MyCookie1(0), "=")(1), Split(MyCookie1(1), "=")(1))
          Cookie1.Secure = True
          Cookie1.HttpOnly = True
          Cookie1.Domain = New Uri(URL).Host

          Dim MyCookie2 = Split(MyCookies(1), ";")
          Cookie2 = New Cookie(Split(MyCookie2(0), "=")(0), Split(MyCookie2(0), "=")(1), Split(MyCookie2(1), "=")(1))
          Cookie2.Secure = True
          Cookie2.Domain = New Uri(URL).Host
        End If
      Next
      Dim myReader = New System.IO.StreamReader(myResp.GetResponseStream)
      Dim ReturnValue As String = myReader.ReadToEnd
      Return ReturnValue
    Catch ex As Exception
      System.Diagnostics.Debug.Print("Error: " & ex.Message)
      Throw ex
    End Try
  End Function

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

  /////////////////////////////////////////////////////////////////////////////////////////

End Class
