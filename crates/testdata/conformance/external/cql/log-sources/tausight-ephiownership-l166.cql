$tausight/ephi-risk-posture:Tausight_ePHIStoredWithJoins()
|HostName=?HostName
|encrypted=?Encryption
|Type=?DeviceType
|age:=?Age
|OwnerName=?OwnerName
|DriveId=?Drive
|case{ not in(field="Activity", values=[Email, "Cloud share"]) | parseTimestamp(as=lt, field=LastAccessed); *|parseTimestamp(as=lt, field=timestamp)}
|eval(curr_age = (now() - lt)/(24*3600*1000))
|test(curr_age >= age)
|cal_age:=math:floor("curr_age")

// clear subset of fileDeleted events that are most recent
//  this saved query also contains an alternative match query that runs 40% faster but less accurate but commented out
|$tausight/ephi-risk-posture:Tausight_FileDeletedMatch()

|groupBy([ OwnerName],function=[count(FileName,distinct=true), groupBy([FileName],function=selectFromMax(@timestamp, include=[@timestamp,cal_age]), limit=max)])
// |groupBy([ OwnerName],function=[groupBy([FileName],function=selectFromMax(@timestamp, include=[cal_age]))], limit=max)

|case{
    cal_age>=0 and cal_age<=30 | series_age:=30;
    cal_age>=31 and cal_age<=60 | series_age:=60;
    cal_age>=61 and cal_age<=90 | series_age:=90;
    cal_age>=91 and cal_age<=180| series_age:=180;
    cal_age>=181 and cal_age<=365| series_age:=365;
    cal_age>=366 and cal_age<=730| series_age:=730;
    cal_age>=731 and cal_age<=1825| series_age:=1825;
    cal_age>=1826 and cal_age<=3650| series_age:=3650;
    cal_age>=3651 | series_age:=3651
}
|top([series_age, OwnerName])
|sort(series_age, order=asc)

|case{
    series_age=30 | series_age:="0 - 30 days";
    series_age=60 | series_age:="31 - 60 days";
    series_age=90 | series_age:="61 - 90 days";
    series_age=180| series_age:="91 - 180 days";
    series_age=365| series_age:="181 days - 1 year";
    series_age=730| series_age:="1 - 2 years";
    series_age=1825| series_age:="2 - 5 years";
    series_age=3650| series_age:="5 - 10 years";
    series_age=3651 | series_age:="> 10 years"
}