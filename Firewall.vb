Imports System.Text
Imports System.Net
Imports System.Net.NetworkInformation
Imports System.Linq
Imports Microsoft.VisualBasic

Public Module Firewall
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //                                                                                                               //
  // Firewall communication - we assume that the firewall is the gateway of this machine                           //
  //                                                                                                               //
  // The only implemented parts are needed for the KerioIPBlocker                                                  //
  //                                                                                                               //
  // More API information, see:                                                                                    //
  // https://www.gfi.com/products-and-solutions/network-security-solutions/kerio-control/resources/developer-zone  //                                                                                 //
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  Property AdminPassword As String

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
  Public Sub Login
    Dim Result = CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.login"",""params"":{""userName"":""admin"",""password"":""" & AdminPassword & """,""application"":{""name"":""KerioIPBlocker"",""vendor"":""buildIT IT-Solutions BV"",""version"":""1.0""}}}")
    Result = Result.Substring(Result.IndexOf("""token"":")+9)
    Cookie = Result.Substring(0, Result.Length - 3)
  End Sub

  //Logout from the firewall
  Public Sub Logout
    //confirm change
    Dim time = CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.getConfigTimestamp""}")
    time = time.Substring(time.IndexOf("""timestamp"":")+12)
    time = time.Substring(0, time.IndexOf("}"))
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.confirmConfig"",""params"":{""clientTimestampList"":[{""name"":""config"",""timestamp"":" & time & "}]}}")

    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Session.logout"", ""params"":{}}")
    Cookie = Null
  End Sub

  //Get the IP Address Groups
  Public Function GetIPAddressGroups As String()
    Return Split(CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.get"",""params"":{""query"":{""orderby"":[{""columnName"":""groupId"", ""direction"":""Asc""}]}}}"), "},{")
  End Function

  //Remove an entry from the IP Address Groups
  Public Sub RemoveIPEntry(Id As String)
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.remove"",""params"":{""groupIds"":[" & Id & "]}}")
  End Sub

  //Add a hos entry to the IP Address Groups
  Public Sub AddIPEntry(GroupId As String, GroupName As String, Ip As String)
    Dim Description = Date.Now.ToString
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.create"",""params"":{""groups"":[{""groupId"": """ & GroupId & """,""groupName"":""" & GroupName & """,""enabled"":true,""description"":""" & Description & """,""host"":""" & Ip & """,""Type"":""Host""}]}}")
  End Sub

  //Apply IP Group changes
  Public Sub ApplyIPChanges
    CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""IpAddressGroups.apply""}")
  End Sub

  Private FromLine = 0
  Public Function GetConnectionLog As String
    Dim myReq As HttpWebRequest
    For i As Integer = 0 To 1
      //This RPC call returns a download link
      Dim Result = CallRpc("{""jsonrpc"":""2.0"",""id"":1,""method"":""Logs.exportLog"",""params"":{""logName"":""connection"",""fromLine"":" & FromLine.ToString & ",""countLines"":-1,""type"":""PlainText""}}")
      Result = Result.Substring(Result.IndexOf("""url"":")+7)
      Dim download = Result.Substring(0, Result.IndexOf(""""))

      //download the log
      Try
        myReq = DirectCast(HttpWebRequest.Create(download), HttpWebRequest)
        Exit For
      Catch
        //Log has been cleared
        FromLine = 0
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

    FromLine += Split(ReturnValue, Chr(13) & Chr(10)).Length - 1
    Return ReturnValue
  End Function


  /////////////////////////////////////////////////////////////////////////////////////////


  // implementation ///////////////////////////////////////////////////////////////////////

  //Do an RPC call to the firewall
  Public Function CallRpc(JsonData As String) As String
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

  /////////////////////////////////////////////////////////////////////////////////////////

End Module