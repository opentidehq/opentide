# prod:function_call valid
groupby([ioc[0].indicator, source.ip], function=[selectlast(@timestamp), count()], limit=max)
| array:contains(array="`filters.not-values`[]", value="9847598475")
| sort(hostname, order=asc)
