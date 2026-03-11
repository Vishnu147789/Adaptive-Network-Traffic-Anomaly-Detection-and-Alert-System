import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense

# Load dataset
df = pd.read_csv("data/cicids2017_cleaned.csv")

print("Dataset Loaded Successfully")
print("Dataset Shape:", df.shape)

# Separate features and label
X = df.drop("Attack Type", axis=1)
y = df["Attack Type"]

# Train autoencoder only on normal traffic
normal_data = X[y == "Normal Traffic"]

print("\nNormal traffic samples:", normal_data.shape)

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(normal_data)

# Split dataset
X_train, X_test = train_test_split(
    X_scaled,
    test_size=0.2,
    random_state=42
)

print("Training samples:", X_train.shape)
print("Testing samples:", X_test.shape)

# Define Autoencoder Architecture
input_dim = X_train.shape[1]

input_layer = Input(shape=(input_dim,))

# Encoder
encoded = Dense(32, activation="relu")(input_layer)
encoded = Dense(16, activation="relu")(encoded)

# Decoder
decoded = Dense(32, activation="relu")(encoded)
decoded = Dense(input_dim, activation="linear")(decoded)

# Autoencoder Model
autoencoder = Model(inputs=input_layer, outputs=decoded)

autoencoder.compile(
    optimizer="adam",
    loss="mse"
)

print("\nTraining Autoencoder...")

# Train model
history = autoencoder.fit(
    X_train,
    X_train,
    epochs=10,
    batch_size=256,
    validation_data=(X_test, X_test),
    verbose=1
)

print("\nAutoencoder Training Completed")

# Reconstruction error
reconstructions = autoencoder.predict(X_test)

mse = np.mean(np.power(X_test - reconstructions, 2), axis=1)

# Define anomaly threshold
threshold = np.mean(mse) + 3 * np.std(mse)

print("\nAnomaly Detection Threshold:", threshold)