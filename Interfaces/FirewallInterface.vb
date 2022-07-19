Public Interface FirewallInterface

  //The password to use when the software connects to the firewall
  Property AdminPassword As String

  //Login to the firewall
  Sub Login

  //Logout from the firewall
  Sub Logout

  //Gets a complete IP address group from the firewall
  Function GetIPAddressGroup(GroupName As String) As RemObjects.Elements.RTL.List(Of GroupEntry)

  //Removes an IP Address group entry
  Sub RemoveIPEntry(entry As GroupEntry)

  //Adds an IP Address group entry
  Sub AddIPEntry(entry As GroupEntry)

  //Get the IP Addresses logged in the connection logs - the implementation should make sure every log entry is only read once
  Function GetConnectionIPAdresses As RemObjects.Elements.RTL.List(Of String)

  //Apply the changes made to the Address groups
  Sub ApplyIPChanges

End Interface

Public Structure Group
  Public Id As String   //Id of the group
  Public Name As String //Name of the group
End Structure

//Group entry to store an Ip Address group entry from the firewall
Public Structure GroupEntry
  Public Group As Group   //The group

  Public ID As String   //Id of the entry (line)
  Public IP As String   //IP Address of the entry
  Public Desc As String //Description of the entry
End Structure
