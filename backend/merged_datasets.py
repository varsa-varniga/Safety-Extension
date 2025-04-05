import pandas as pd
from scipy.io import arff

# Step 1: Convert ARFF to CSV
print("🔄 Converting ARFF to CSV...")
data, meta = arff.loadarff('Training Dataset.arff')
df_arff = pd.DataFrame(data)

# Decode byte strings
for column in df_arff.columns:
    if df_arff[column].dtype == object:
        df_arff[column] = df_arff[column].str.decode('utf-8')

df_arff.to_csv("converted_dataset.csv", index=False)
print("✅ ARFF file converted and saved as converted_dataset.csv")

# Step 2: Load all datasets
try:
    df_base = pd.read_csv("dataset.csv")
    print(f"📁 Loaded dataset.csv - Shape: {df_base.shape}")
except Exception as e:
    print("❌ Failed to load dataset.csv:", e)
    df_base = pd.DataFrame()

try:
    df_uci = pd.read_csv("Phishing_Legitimate_full.csv")
    print(f"📁 Loaded Phishing_Legitimate_full.csv - Shape: {df_uci.shape}")
except:
    df_uci = pd.DataFrame()

try:
    df_kaggle = pd.read_csv("converted_dataset.csv")
    print(f"📁 Loaded converted_dataset.csv - Shape: {df_kaggle.shape}")
except:
    df_kaggle = pd.DataFrame()

# Step 3: Align all datasets to base dataset columns
base_columns = df_base.columns.tolist()

df_uci = df_uci.reindex(columns=base_columns)
df_kaggle = df_kaggle.reindex(columns=base_columns)

# Step 4: Combine all datasets
df_combined = pd.concat([df_base, df_uci, df_kaggle], ignore_index=True)

# Step 5: Drop rows missing crucial label (e.g., 'Result' or 'CLASS_LABEL')
label_column = "Result" if "Result" in df_combined.columns else "CLASS_LABEL"
df_combined.dropna(subset=[label_column], inplace=True)

# Step 6: Remove duplicates if URL column exists
if 'url' in df_combined.columns:
    df_combined.drop_duplicates(subset='url', inplace=True)

# Optional: Shuffle the dataset
df_combined = df_combined.sample(frac=1).reset_index(drop=True)

# Step 7: Save merged dataset
df_combined.to_csv("merged_dataset.csv", index=False)
print(f"✅ Final merged dataset saved with shape: {df_combined.shape}")
