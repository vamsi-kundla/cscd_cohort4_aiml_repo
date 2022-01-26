from bs4 import BeautifulSoup
import pandas as pd 
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn import preprocessing
enc = preprocessing.LabelEncoder()

normal_data = ['./dataset/allNormals1.xml']
anomalies_data = ['./dataset/allAnomalies1.xml', './dataset/allAnomalies2.xml']
attacks_data = ['./dataset/allAttacks1.xml', './dataset/allAttacks2.xml', './dataset/allAttacks3.xml', './dataset/allAttacks4.xml', './dataset/allAttacks5.xml']

def get_data():
    
    data = pd.DataFrame()

    for filePath in normal_data:
        df1 = pd.read_xml(filePath, xpath='.//request')
        df1['label'] = 'normal'

    for filePath in anomalies_data:
        df2 = pd.read_xml(filePath, xpath='.//request')
        df2['label'] = 'anomalous'

    for filePath in attacks_data:
        df3 = pd.read_xml(filePath, xpath='.//request')
        df3['label'] = 'attack'

    frames = [df1, df2, df3]

    data = pd.concat(frames)
    data = data.reset_index(drop=True)
    # print(data.head())
    return data

data = get_data()
print(data)

model = LinearRegression()

x = data[['method', 'protocol', 'path', 'headers', 'query', 'body']]

y = data['label']

enc.fit(data['path'])
# print(data)
print(enc.classes_)

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=0)

# model.fit(x_train, y_train)

# predictions = model.predict(x_test)

# plt.hist(y_test - predictions)
