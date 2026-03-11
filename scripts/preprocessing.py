import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

# Load dataset
df = pd.read_csv("data/cicids2017_cleaned.csv")

print("Dataset Loaded Successfully")

# Show dataset shape
print("\nDataset Shape:")
print(df.shape)

# Show first 5 rows
print("\nFirst 5 rows:")
print(df.head())

# Show column names
print("\nColumns:")
print(df.columns)

# Separate features and label
X = df.drop("Attack Type", axis=1)
y = df["Attack Type"]

# Convert attack labels to numbers
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

print("\nAttack Classes:")
print(list(encoder.classes_))

# Split dataset into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42
)

print("\nTraining Set Shape:")
print(X_train.shape)

print("\nTesting Set Shape:")
print(X_test.shape)

print("\nPreprocessing Completed Successfully")