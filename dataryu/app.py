# app.py

import statistics

data = [11, 21, 11, 19, 46, 21, 19, 29, 21, 18, 3, 11, 11]

x = statistics.mean(data)
print(x)

y = statistics.median(data)
print(y)

z = statistics.mode(data)
print(z)

a = statistics.stdev(data)
print(a)

b = statistics.variance(data)
print(b)