import sqlite3

conn = sqlite3.connect('data/sentinel.db')
c = conn.cursor()
c.execute('SELECT id, filename, status, total_chunks, completed_chunks, failed_chunks, error_message FROM analysis_jobs ORDER BY created_at DESC LIMIT 5')
for j in c.fetchall():
    print("Job:", j)

c.execute('SELECT id, job_id, chunk_index, status FROM log_chunks WHERE status != "COMPLETED" ORDER BY id DESC LIMIT 15')
for ch in c.fetchall():
    print("Non-completed chunk:", ch)

c.execute('SELECT chunk_index, status FROM log_chunks WHERE job_id = (SELECT id FROM analysis_jobs ORDER BY created_at DESC LIMIT 1) GROUP BY status, chunk_index LIMIT 20')
print("Status breakdown for latest job:")
for s in c.fetchall():
    print(s)
