import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import tensorflow as tf

from tensorflow.keras import layers
from tensorflow.keras.models import Model
from tensorflow.keras import regularizers
from statsmodels.stats.outliers_influence import variance_inflation_factor
from sklearn.preprocessing import StandardScaler, normalize
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split

# To import as module for testing:
# from importlib import import_module
# a = importmodule('features')

# Show malware distribution within dataset
def malware_distribution(data, label):
    # Specify data column to calculate
    target = data[label]
    # Get dataset length for percentage calculation
    total = len(data)
    # Define graph area and title
    plt.figure(figsize = (6, 6))
    plt.title("{} Dataset Percentage".format(label))

    # Generate count plot and turn into bar graph for display
    ax = sns.countplot(target)
    for p in ax.patches:
        percentage = '{:.0f}%'.format(p.get_height() / total * 100)
        x = p.get_x() + p.get_width() / 2
        y = p.get_height() + 5
        ax.annotate(percentage, (x, y), ha = 'center')

    plt.show()

def dataset_heatmap (data, label, annotate=False):
    #Gausidan distrabution of dataset
    data_features = data.drop(label, axis=1)
    data_standard_dev = (data_features - data_features.mean()) / data_features.std()
    gaussian_data = pd.concat([data[label], data_standard_dev], axis=1)

    # Define plot area
    plt.figure(figsize = (10, 8))
    plt.title("Correlation Heatmap")
    correlation = gaussian_data.corr()
    if annotate:
        sns.heatmap(correlation, annot = annotate, fmt = '.2f', cmap = 'coolwarm')
    else:
        sns.heatmap(correlation, annot = annotate, cmap = 'coolwarm')
    
    plt.show()

def calculate_vif (data, label):
    data = data.drop(label, axis=1)
    vif_data = pd.DataFrame()
    vif_data['feature'] = data.columns
    vif_data['VIF'] = [variance_inflation_factor(data.values, i) for i in range(len(data.columns))]

    for feature in vif_data:
        print(feature)

def mal_ben_hist (data, label, graph_set, benign_percent):
    malware_label = data.malware_label
    # Remove malware label
    data = data.drop(label, axis=1)
    #std_data = StandardScaler().fit_transform(data)
    norm_data = normalize(data)
    data = pd.DataFrame(norm_data, columns = data.columns)
    _, axes = plt.subplots(10, 3, figsize=(12, 9)) # 3 columns containing 10 figures

    begin = graph_set * 30
    end = begin + 30
    data_to_graph = data.iloc[:, begin:end]

    data_to_graph = pd.concat([data_to_graph, malware_label], axis=1)
    malware = data_to_graph[data_to_graph.malware_label == 1]
    benign = data_to_graph[data_to_graph.malware_label == 0]
    # Get a percentage of the benign data set to balance measurements for analysis
    # This can be changed to view graphs differently, but is very helpful to truly
    # see the differences between benign and malicious traffic side by side
    percent = int(len(malware) * (benign_percent / 100))
    benign = data_to_graph.sample(n=percent)
    ax = axes.ravel()
    for i in range(data_to_graph.shape[1] - 1):
        _, bins = np.histogram(data_to_graph.iloc[:, i], bins=40)
        ax[i].hist(malware.iloc[:, i], bins=bins, color='r', alpha=.5) # Red for malware
        ax[i].hist(benign.iloc[:, i], bins=bins, color='g', alpha=0.3) # Green for benign
        ax[i].set_title(data_to_graph.columns[i], fontsize=9)
        ax[i].axes.get_xaxis().set_visible(False) # Just want to see separation not measurements
        ax[i].set_yticks(())
    
    ax[0].legend(['malware', 'benign'], loc='best', fontsize=8)
    plt.tight_layout()
    plt.show()


def calculate_pca (data, label, graph):
    features = data.columns
    # Remove features from data
    data_vals = data.loc[:, features].values
    # Define the target/label
    #data_label = data.loc[:, [label]].values
    # Standardize the dataset
    std_data = StandardScaler().fit_transform(data_vals)

    # Calculate the 10 most important components
    pca = PCA(n_components = 10)
    data_pca_vals = pca.fit_transform(std_data)
    pca_dataframe = pd.DataFrame(data = data_pca_vals)
    final_pca_dataframe = pd.concat([pca_dataframe, data[[label]]], axis=1)

    if graph == 'heatmap':
        correlation = final_pca_dataframe.corr()
        sns.heatmap(correlation, annot=True, fmt='.2f', cmap = 'coolwarm')
    elif graph == 'pairplot':
        sns.pairplot(final_pca_dataframe, kind='scatter', hue=label, markers=['o', 's'], palette='Set2')
    plt.show()

def autoencoded_features (data, label, graph):
    data = data.drop([label], axis=1)
    #std_data = StandardScaler().fit_transform(data)
    data = normalize(data)

    ae_input_features = len(data.columns)
    round_one_hidden_units = 150
    round_two_hidden_units = 100
    round_three_hidden_units = 50
    round_four_hidden_units = 10

    ae_inputs = tf.keras.Input(shape=(ae_input_features,))
    ae_encoded = layers.Dense(round_one_hidden_units, activation='relu',
                        activity_regularizer=regularizers.l1(10e-5))(ae_inputs)
    ae_encoded = layers.Dense(round_two_hidden_units, activation='relu',
                        activity_regularizer=regularizers.l1(10e-5))(ae_encoded)
    ae_encoded = layers.Dense(round_three_hidden_units, activation='relu',
                        activity_regularizer=regularizers.l1(10e-5))(ae_encoded)
    ae_encoded = layers.Dense(round_four_hidden_units, activation='relu',
                        activity_regularizer=regularizers.l1(10e-5))(ae_encoded)

    encoder = Model(inputs=ae_inputs, outputs=ae_encoded)
    encoded_data = pd.DataFrame(encoder.predict(data))
    encoded_data.columns = ['feat_1', 'feat_2', 'feat_3', 'feat_4', 'feat_5', 'feat_6', 'feat_7', 'feat_8', 'feat_9', 'feat_10']
    if graph == 'pairwise':
        sns.pairplot(encoded_data, kind='scatter', markers=['o', 's'], palette='Set2')
    elif graph == 'heatmap':
        correlation = encoded_data.corr()
        sns.heatmap(correlation, annot=True, fmt='.2f', cmap = 'coolwarm')
    plt.show()


#def load_input (csv_data_file):
csv_data_file = 'test_train_data-all.csv'
dataset = pd.read_csv(csv_data_file)
# Remove columns filled with all 0 value (these will be statistically insignifant and will cause
# issues when using correlation methods of analysis)
data_no_z_cols = dataset.loc[:, (dataset != 0).any(axis=0)]
