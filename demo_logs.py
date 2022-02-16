import requests
file1 = open('access.txt', 'r')

# Using for loop
print("Using for loop")
for line in file1:
    print(line)
    line_data = {"data": line}
    requests.post('http://127.0.0.1:5000/classify', data=line_data)

# Closing files
file1.close()