import requests
import json
import mysql.connector
import csv
from datetime import datetime
from datetime import timedelta

Api_url    = 'https://www.virustotal.com/vtapi/v2/url/report'
Api_Domain = 'https://www.virustotal.com/vtapi/v2/domain/report'
Api_key    = 'b1f5e34beb2104d0bf303bd928f4b520b8b8d6f3207026a29c82de3d3702414e'

def get_virustotal_url_data_from_api(url): #get
    params = dict(apikey=Api_key, resource=url)
    response = requests.get(Api_url, params=params)
    if response.status_code >= 200 and response.status_code < 300:
       result = response.json()
       #print(json.dumps(result, sort_keys=False, indent=4))
       return result

def get_virustotal_domain_data_from_api(Domain):
    params = dict(apikey=Api_key, domain=Domain)
    response = requests.get(Api_Domain, params=params)
    if response.status_code >= 200 and response.status_code < 300:
       result = response.json()
       #print(json.dumps(result, sort_keys=False, indent=4))
       return result

##לבדוק על השוואה בין תאריכים
'''def minutes_between(d1, d2):
    delta = timedelta(d2-d1)
    print("diff date:",delta.minutes)
    return delta.minutes
    #return abs((d2 - d1).minutes)
'''

def Handle_Url(mydb, Url):
          #myCursor = mydb.cursor()
          myCursor_Dict = mydb.cursor(dictionary=True)

          ########################### Query ###########################
          select= "select * from sys.urls_tailormed where Url='"+Url+"';"
          #print("SELECT query", select)

          now = datetime.now()

          myCursor_Dict.execute(select)
          myresult = myCursor_Dict.fetchone()

          if(myresult == None or len(myresult) == 0):
              #case of url not present in DB#
              #print("0 results")

              #data_Url = get_virustotal_url_data_from_api(Url)
              data_Domain = get_virustotal_domain_data_from_api(Url)

              '''
              if (data_Domain["Webutation domain info"]["Verdict"] == "malicious"
                      or
                  data_Domain["Webutation domain info"]["Verdict"] == "malware"
                      or
                  data_Domain["Webutation domain info"]["Verdict"] == "phising"):

                  risk = "risk"
                  print("risk")
                  
              else:
                  risk = "safe"
                  print("safe")
              '''
              #noא Working two field #
              risk = "safe"
              voting = "unspecifid"

              #category =  data_Domain["BitDefender category"]

              if "BitDefender category" in data_Domain:
                  category = data_Domain["BitDefender category"]

              elif "alphaMountain.ai category" in data_Domain:
                  category = data_Domain["alphaMountain.ai category"]

              elif "Forcepoint ThreatSeeker category" in data_Domain:
                  category = data_Domain["Forcepoint ThreatSeeker category"]

              elif "Comodo Valkyrie Verdict category" in data_Domain:
                  category = data_Domain["Comodo Valkyrie Verdict category"]

              mySql_insert_query = "INSERT INTO sys.urls_tailormed (Url,Risk,Voting,Category,Timestamp)"
              mySql_insert_query += "VALUES('"+Url+"','"+risk+"' , '"+voting+"', '"+category+"', '"+str(now)+"')"
              #print("insert query", mySql_insert_query)


              myCursor_Dict.execute(mySql_insert_query)

              mydb.commit()
              print(myCursor_Dict.rowcount,"Insert : "+Url+ "inserted successfully into urls_tailormed table")
          else:
              #case of url is present in DB
              print("DEBUG", myresult)

              #getResultTS = myresult["Timestamp"]

              select_DateDiff="select TIMESTAMPDIFF(MINUTE,Timestamp,NOW())  from sys.urls_tailormed where Url='"+Url+"';"

              #mins_between = minutes_between(getResultTS, now)
              #print("minutes between", mins_between)

              if(select_DateDiff < '30'):  return
              data_Domain = get_virustotal_domain_data_from_api(Url)

              mySql_update_query =                  """UPDATE sys.urls_tailormed                                                                                                
                                                       set Risk='"+risk+"', Voting='"+voting+"', Category='"+category+"', TimeStamp='"+str(now)+"'
                                                       WHERE url='"+Url+"' 
                                                       """
                                                      # set Risk={data.Risk}, Voting={data.Voting}, Category={data.Category}, TimeStamp={now}


              #print("update query", mySql_update_query)
              myCursor_Dict.execute(mySql_update_query)

              mydb.commit()
              #print(myCursor_Dict.rowcount, "Record updated successfully into urls_tailormed table")





#________Get URlS From CSV and return Url to Func That call Him = separate_Uarls()_____________#
def GetURlS():
    url_list = []
    with open('urls.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
                #print(f'URL:\t{row[0]}'f'')
                url_list.append(row[0])
                line_count += 1
        print(f'Processed {line_count} lines.')
    return url_list

#_______________call To func GetURlS() and send Url  and db = To func Handle_Url ()________________#
def separate_Uarls(mydb):
    Urls_From_CSV = GetURlS()
    i=0
    for Url in Urls_From_CSV:
        Handle_Url(mydb, Url)
        i += 1

#___________________#Connect To Db_________________________________#
def connect_to_db():
    try:
        mydb = mysql.connector.connect(host='127.0.0.1',user='root',password='Ys@12345',port='3306',database='sys')
        print('Log in successfully')

        return mydb
       #checks
       #print ('Open curser')
       #myCursor.execute('show tables')
       #for i in myCursor:
         # print(i)
        #call to Func
       #InsertData(myCursor,mydb, result ,"Url_1")

    except Exception as ex:
        print("Connection could not be made due to the following error: \n",ex)
        return None

#___________________MAIN___________________#
mydb=connect_to_db()
separate_Uarls(mydb) #CALL TO Funcsion separate_Uarls()
#check if not None


