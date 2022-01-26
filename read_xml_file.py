from bs4 import BeautifulSoup
import pandas as pd 

xml_path = './dataset/allNormals1.xml'

# with open(xml_path, 'r') as f:
#     data = f.read()

# # print(data)
# Bs_data = BeautifulSoup(data, "xml")
# b_unique = Bs_data.find_all('sample')
# print(b_unique)
df = pd.read_xml(xml_path, xpath='.//label')
print(df)