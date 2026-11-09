#category=FilterAlert dataspace=?repository alertName=?alertName
| status=*
| case {
  test(message=="Alert triggered on event and invoked at least one action") | successfulPoll:="true";
  test(message=="Alert found no results and will not trigger")              | successfulPoll:="true";
  *                                                                         | *;
}
| [{status=Failure | count(aid, cid, as=failureCount)}, {status=Success successfulPoll=true | count(as=successPollCount)}, {status=Success successfulPoll!=true | count(as=successCount)}]
| case {
  test(successPollCount>0) | aggStatus:="🟢";
  test(failureCount>0)     | aggStatus:="🔴";
  test(successCount>0)     | aggStatus:="🟢";
  *                        | aggStatus:="⚪";
}
| select(aggStatus)