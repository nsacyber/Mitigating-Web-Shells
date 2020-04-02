import sys
import os.path
import csv


# Script will generate a list of URL that from Apache web access log that have least unique IP address or unique user-agents
# Written for Python 3

# Ideal Percentage of URL to display
#   Will display more base on matching count
urlpercentage = 0.05

# Hold the filename for Apache web access log
weblogfileName = None

# apache log fields
apachelogsfields = ['ip', 'identd', 'frank', 'time_part0', 'time_part1', 'request', 'status', 'size', 'referer', 'user_agent']

# function output the url based on lower counts unique ip address and lower counts of unique user-agents
def analyze_weblog(filename):

    uniqueurlcount = 0                    # count of unique URL in web log
    urls = []                             # list of unique URL, also index into lists of lists of unique ip address and user-agents
    uniqueipcount = []                    # list of unique ip address count for URL 
    uniqueuseragentscount = []            # list of unique use agents for URL
    iplist = []                           # list of list of ip address per unique URL to keep track of unique URL
    useragentlist = []                    # list of list of user-agents per unique URL to keep track of unique user-agents
    
    print("The weblog file to analyze is %s" % filename)
    with open(filename, mode='r') as csv_file:                    # read in web log as csv file
        csv_reader = csv.reader(csv_file, delimiter=' ')
        for row in csv_reader:
     
            # handles simple case where file has comments start with #     
            if (row[0][0] != '#'):        
                                                                    # extract only fields of interest from the web log
               ipaddress = row[apachelogsfields.index('ip')]        # ip address     
               request = row[apachelogsfields.index('request')]     # request (URL part of request) 
               status = row[apachelogsfields.index('status')]       # user-agent
               user_agent = row[apachelogsfields.index('user_agent')]
    #           print('ipaddress: %s request: %s status: %s user_agent: %s' % (ipaddress, request, status, user_agent))
               url = (request.partition(' ')[2]).partition(' ')[0]  # extract URL from request field
    #           print ('url %s' % url)
               if (status >= '200' and status <= '299'):            # only request with status of 200 - 299
               
                   if (url not in urls):                        # determine if URL is already been seen
                       uniqueurlcount += 1                      # if not increment unique URL count
                       urls.append(url)                         # append new URL to the unique URL list
                       uniqueipcount.append(0)                  # append an element of zero for the unique ip count list
                       uniqueuseragentscount.append(0)          # append an element of zero for the unique user-agents count list
                       newiplist = []                           # new empty element list for ip address tracking per URL
                       iplist.append(newiplist)                 # append empty list to list of list of ip per URL
                       newuseragentlist = []                    # new empty element list for user-agents tracking per URL
                       useragentlist.append(newuseragentlist)   # append empty list to list of list of user-agents per URL

                   if (user_agent not in useragentlist[urls.index(url)]):  # determine if user-agents is in the particular URL list
                       useragentlist[urls.index(url)].append(user_agent)   # if not append user-agents to user-agents list for the particular URL list
                       temp = uniqueuseragentscount[urls.index(url)] + 1   # also increment unique user-agents count for that URL
                       uniqueuseragentscount[urls.index(url)] = temp
                   if (ipaddress not in iplist[urls.index(url)]):              # determine if ip address is in the particular URL list
                       iplist[urls.index(url)].append(ipaddress)               # if not append ip address to ip address list for the particular URL list
                       temp = uniqueipcount[urls.index(url)] + 1               # also increment unique ip address count for that URL
                       uniqueipcount[urls.index(url)] = temp                       
               
           
#        print(urls)
#        print('uniqueurlcount: %s' % uniqueurlcount)
#        print(uniqueuseragentscount)
#        print(uniqueipcount)
#        print('amount of useragentlist: %s' %  len(uniqueuseragentscount))
#        print('amount in the iplist: %s' % len(uniqueipcount))
        numberofurltodisplay = urlpercentage * uniqueurlcount       # Determine line that represent percentage of URL wanted
        intnumberofurltodisplay = int(numberofurltodisplay)
        if (numberofurltodisplay > intnumberofurltodisplay):        # Round up 
            intnumberofurltodisplay += 1
        tempuniqueuseragentscount = uniqueuseragentscount.copy()    # Create a temporary copy of list of unqiue user-agents count to sort
        tempuniqueuseragentscount.sort()
                                                                    # Array start at 0 need to subtract -1 from index
        useragentcounttodisplay = tempuniqueuseragentscount[(intnumberofurltodisplay -1)] # determine the count of unique user-agents to display
        tempuniqueipcount = uniqueipcount.copy()                    # Create a temporary copy of list of unqiue ip address count to sort
        tempuniqueipcount.sort()
                                                                    # Array start at 0 need to subtract -1 from index
        ipcounttodisplay = tempuniqueipcount[(intnumberofurltodisplay -1)]                # determine the count of ip address to display
    
        print('URL with least user agents')
        print('--------------------------')
        
        for count in range (0, (useragentcounttodisplay + 1)):  # Increament thru count to count of unique user-agents to display to order url output based on count
            index = 0
            for elementuseragentcount in uniqueuseragentscount:         # Increment thru unique user-agents count list
               if (elementuseragentcount == count):                     #    List URL where where user-agents is equal to count 
                   print(urls[index])
               index += 1
               
        print('URL with least IP address')         
        print('-------------------------')           
        
        for count in range (0, (ipcounttodisplay + 1)):    # Increament thru count to count of unique ip address to display to order url output based on count
            index = 0
            for elementipcount in uniqueipcount:                        # Increment thru unique ip address count list
               if (elementipcount == count):                            #    List URL where where user-agents is equal to count
                   print(urls[index])
               index += 1           
        
if __name__ == '__main__':
   try:
       if len(sys.argv) == 2:                                              # Simple check if an agrument is passed (assume weblog file
           weblogfileName=sys.argv[1]
           print ("Web log file to read is %s" % weblogfileName)
           if(os.path.isfile(weblogfileName)):
                analyze_weblog(weblogfileName)             
       else:
           print ('Usage: python3 %s <weblogfile>' % sys.argv[0])         # Print usage statement
   except Exception as e:
        print("You must provide a valid filename (path) of a web logfile")
        raise
   
