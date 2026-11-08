# prod:argument valid
head(10) | groupBy(status_code, function=count) | timeChart(method, span=5min)
