import pandas as pd

df1 = pd.read_csv("Phishing_Legitimate_full.csv")
df2 = pd.read_csv("dataset.csv")

print("Phishing CSV columns:", df1.columns.tolist())
print("Legitimate CSV columns:", df2.columns.tolist())
