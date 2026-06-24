#!/usr/bin/env python3
import psycopg2, time
print("Content-Type: text/html\n")
try:
    conn = psycopg2.connect(host='10.30.0.6', dbname='waystar', user='waystar-app', password='AppBooking!2026')
    time.sleep(600)
except:
    pass
