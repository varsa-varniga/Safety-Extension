import pandas as pd

# Load phishing and legitimate datasets
phishing_df = pd.read_csv("Phishing_Legitimate_full.csv")
legit_df = pd.read_csv("dataset.csv")

# ✅ Align column names
# Rename phishing dataset label to 'Result' for consistency
phishing_df = phishing_df.rename(columns={"CLASS_LABEL": "Result"})

# Filter common columns
common_columns = set(phishing_df.columns) & set(legit_df.columns)
phishing_df = phishing_df[list(common_columns)]
legit_df = legit_df[list(common_columns)]

# ✅ Add labels: 1 for phishing, -1 for legitimate
phishing_df["Result"] = 1
legit_df["Result"] = -1

# ✅ Merge
combined_df = pd.concat([phishing_df, legit_df], ignore_index=True)

# ✅ Save the clean merged dataset
combined_df.to_csv("clean_dataset.csv", index=False)
print("✅ clean_dataset.csv saved successfully!")
