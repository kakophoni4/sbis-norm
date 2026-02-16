import psycopg2

print("--- Testing psycopg2 ---")
try:
    conn = psycopg2.connect("dbname='tax_db' user='user' host='localhost' password='12345'")
    print("psycopg2: Success!")
    conn.close()
except Exception as e:
    print(f"psycopg2 Error: {e}")