import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

# Load dataset
df = pd.read_csv("phishing_legitimate_full.csv")

print("🧾 Shape:", df.shape)
print("📌 Columns:", df.columns.tolist())

# Split features and label
X = df.drop(columns=["id", "CLASS_LABEL"])
y = df["CLASS_LABEL"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model
with open("phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model trained and saved as phishing_model.pkl")
