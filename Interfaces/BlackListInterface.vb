Public Interface BlackListInterface

  //The API key to use for this blacklist
  Property API_Key As String

  //Checks an IP Address, returns true when the IP address is safe (false for blocked)
  //The implementation should persist all lookups which can be read again with the ReadLookupCache sub
  Function CheckIP(IP As String) As Boolean

  //Reads a predefined blacklist with blocked addresses that will be cached
  //The implementation should do an online download of the blacklist every 12 hours, and should cache this blacklist.
  //When the software is restarted, it should only read a new blacklist when the saved one is older than 12 hours
  //When reading the online or cached blacklist, those addresses should be cached.
  Sub ReadBlacklist

  //Reads the persisted cache
  Sub ReadLookupCache

  //reports an IP Address to the blacklist provider
  Sub ReportIP(ip As String, ports As String)

End Interface
