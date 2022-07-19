Imports System.IO
Imports System.Diagnostics
Imports System.Collections
Imports System.Collections.Generic
Imports Microsoft.VisualBasic

Module Program
  Private Firewall As New KerioFirewall
  Private BlackList As New AbuseIpDbChecker
  Private Property MaxCountOfBlockedAddresses As Integer = 50

  // parameters: -P:AdminPassword -M:MaxCountOfBlockedAddresses -A:APIKeyForAbuseDB
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
        Firewall.AdminPassword = a.Substring(3).trim
      End If
      If a.StartsWith("-M:") Then
        MaxCountOfBlockedAddresses = CInt(Val(a.Substring(3).trim))
      End If
      If a.StartsWith("-A:") Then
        BlackList.API_Key = a.Substring(3).trim
      End If
    Next

    //read the previous done lookups to minimize the amount of needed online lookups
    BlackList.ReadLookupCache
    //cache the blacklist, minimum of 10.000 addresses
    BlackList.ReadBlacklist

    //main loop
    do
      try
        Firewall.Login
        UpdateBlocked(GetIpToBlockFromConnectionLog)
        Firewall.Logout
      Catch
      End Try
      threading.Thread.Sleep(15000) 'sleep 15 seconds

      //read the updated blacklist every 12 hours, update the cache and the TTL for these addresses
      BlackList.ReadBlacklist
    Loop
  End Sub

  Public Function GetIpToBlockFromConnectionLog As RemObjects.Elements.RTL.List(Of String)
    Dim ReturnValue As New RemObjects.Elements.RTL.List(Of String)

    For Each IP As String In Firewall.GetConnectionIPAdresses //connection ip addresses from connection log
      If Not BlackList.CheckIP(IP) Then
        //This IP is listed In AbuseIP DB -> Add to the IP Adresses to block
        ReturnValue.Add(IP)
      End If
    Next
    Return ReturnValue
  End Function


  Public Sub UpdateBlocked(IpsToBlock As RemObjects.Elements.RTL.List(Of String))
    Dim CurrentlyBlocked As New SortedDictionary(Of DateTime, GroupEntry)
    Dim Grp As New Group With {.Id = "AbuseIP_DB_Blocked_ID", .Name = "AbuseIP DB Blocked"}

    //loop the current address group and remove all entries where the TTL expired
    For Each l As GroupEntry In Firewall.GetIPAddressGroup(Grp.Name)

      Grp.Id = l.Group.Id //get the real group id instead of the placeholder defined earlier

      If l.Desc <> "PlaceHolder" Then //skip placeholder entries

        //get the TTL from the desciption
        Dim TTL As Date
        Try
          //get the date time this entry was added and add 1 day to get the valid to date time
          TTL = Microsoft.VisualBasic.DateAndTime.DateAdd(Microsoft.VisualBasic.DateInterval.Day, 1, DateTime.Parse(l.Desc))
        Catch
          TTL = New Date //not a valid date time in the description - so we remove the entry
        End Try

        If TTL < Now Then
          //entry is not valid anymore, so remove the entry from the group
          Firewall.RemoveIPEntry(l)
        Else

          //still valid, so this one is blocked
          //prevent duplicated keys in the dictionary
          Do While CurrentlyBlocked.ContainsKey(TTL)
            TTL = Microsoft.VisualBasic.DateAndTime.DateAdd(Microsoft.VisualBasic.DateInterval.Second, 1, TTL)
          Loop

          CurrentlyBlocked.Add(TTL, l)
        End If

        If IpsToBlock.Contains(l.IP) Then
          //This IP is already blocked, so we don't need it in the IpsToBlock list
          IpsToBlock.Remove(l.IP)
        End If
      End If
    Next

    //Now we are going to block all new addresses
    For Each IpEntry As String In IpsToBlock
      //create the new entry
      Dim AddGrp As New GroupEntry
      With AddGrp
        .Group = Grp
        .ID = "-1"
        .IP = IpEntry
      End With
      Firewall.AddIPEntry(AddGrp)
      CurrentlyBlocked.Add(Now, AddGrp)
    Next

    //Check if we have too much blocked addresses - if so, free the oldest ones
    Dim TotalBlocked = CurrentlyBlocked.Count

    For Each dt As DateTime In CurrentlyBlocked.Keys
      If TotalBlocked > MaxCountOfBlockedAddresses Then

        //don't remove entries we just added
        If CurrentlyBlocked(dt).ID <> "-1" Then
          Firewall.RemoveIPEntry(CurrentlyBlocked(dt))
          TotalBlocked -= 1
        End If
      Else
        Exit For //we are done, no more addresses to remove
      End If
    Next

    //Apply the changes
    Firewall.ApplyIPChanges
  End Sub


End Module
