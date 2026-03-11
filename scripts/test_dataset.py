import pandas as pd

df = pd.read_csv("data/cicids2017_cleaned.csv")

print(df.head())

print("\nColumns:")
print(df.columns)

print("\nLabel distribution:")
print(df['Attack Type'].value_counts())