import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import tensorflow as tf

from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.models import Model
from tensorflow.keras import regularizers
from tensorflow.random import set_seed
from statsmodels.stats.outliers_influence import variance_inflation_factor
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from tensorflow.keras.callbacks import ModelCheckpoint, TensorBoard, LearningRateScheduler
from sklearn.metrics import confusion_matrix, precision_recall_curve, recall_score, classification_report, auc, roc_curve, accuracy_score, precision_recall_fscore_support, f1_score
from numpy.random import seed

# To import as module for testing:
# from importlib import import_module, reload
# a = import_module('features')
# Use this when you make changes
# reload(a)

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
    #norm_data = normalize(data)
    mm_data = MinMaxScaler().fit_transform(data)
    data = pd.DataFrame(mm_data, columns = data.columns)
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
    percent = int(len(benign) * (benign_percent / 100))
    benign = benign.sample(n=percent)
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
    data_label = data.loc[:, [label]].values
    # Normalize the dataset
    std_data = MinMaxScaler().fit_transform(data_vals)

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

def autoencoded_features (data, label, graph, final_features):
    # Balance dataset based on percentage passed to function
    seed(1)
    set_seed(2)
    SEED = 123
    DATA_SPLIT_PCT = 0.2
    #malware = data[data.malware_label == 1]
    #benign = data[data.malware_label == 0]
    #percent = int(len(malware) * (benign_percent / 100))
    #benign = benign.sample(n=percent)
    #malware = malware.sample(n=percent)
    #data = benign.append(malware).reset_index()

    # Prune and scale dataset for analysis
    #label_col = data[label]
    #data = data.drop([label], axis=1)
    #features = list(data.columns)
    #data[features] = MinMaxScaler().fit_transform(data[features])

    # Split into training and testing datasets
    #x_train, x_test, y_train, y_test = train_test_split(data[features], label_col, test_size=0.3, random_state=1)
    x_train, x_test = train_test_split(data, test_size=DATA_SPLIT_PCT, random_state=SEED)
    x_train, x_valid = train_test_split(x_train, test_size=DATA_SPLIT_PCT, random_state=SEED)
    
    x_train_0 = x_train.loc[data[label] == 0]
    x_train_1 = x_train.loc[data[label] == 1]
    x_train_0_x = x_train_0.drop([label], axis=1)
    x_train_1_x = x_train_1.drop([label], axis=1)

    x_valid_0 = x_valid.loc[data[label] == 0]
    x_valid_1 = x_valid.loc[data[label] == 1]
    x_valid_0_x = x_valid_0.drop([label], axis=1)
    x_valid_1_x = x_valid_1.drop([label], axis=1)

    x_test_0 = x_test.loc[data[label] == 0]
    x_test_1 = x_test.loc[data[label] == 1]
    x_test_0_x = x_test_0.drop([label], axis=1)
    x_test_1_x = x_test_1.drop([label], axis=1)

    scaler = StandardScaler().fit(x_train_0_x)
    x_train_0_x_rescaled = scaler.transform(x_train_0_x)
    x_valid_0_x_rescaled = scaler.transform(x_valid_0_x)
    x_valid_x_rescaled = scaler.transform(x_valid.drop([label], axis=1))

    x_test_0_x_rescaled = scaler.transform(x_test_0_x)
    x_test_x_rescaled = scaler.transform(x_test.drop([label], axis=1))

    # Create set of negative outcomes only
    #x_train_1 = x_train.copy()
    #x_train_1[label] = y_train
    #x_train_1 = x_train_1[x_train_1[label] == 1]
    #x_train_1 = x_train_1.drop(label, axis=1)
    #
    #x_test_1 = x_test.copy()
    #x_test_1[label] = y_test
    #x_test_1 = x_test_1[x_test_1[label] == 1]
    #x_test_1 = x_test_1.drop(label, axis=1)

    # Autoencoder values
    learning_epochs = 200
    batch_size = 128
    input_dim = x_train_0_x_rescaled.shape[1]
    #input_dim = x_train_1.shape[1]
    encoding_dim = int(input_dim / 2)
    hidden_dim_1 = int(encoding_dim / 2)
    hidden_dim_2 = int(hidden_dim_1 / 2)
    final_hidden_dim = final_features
    learning_rate = 1e-6

    input_layer = Input(shape=(input_dim, ))
    encoder = Dense(encoding_dim, activation='relu', activity_regularizer=regularizers.l1(learning_rate))(input_layer)
    encoder = Dense(hidden_dim_1, activation='relu')(encoder)
    encoder = Dense(hidden_dim_2, activation='relu')(encoder)
    encoder = Dense(final_hidden_dim, activation='relu')(encoder)
    decoder = Dense(final_hidden_dim, activation='relu')(encoder)
    decoder = Dense(hidden_dim_2, activation='relu')(decoder)
    decoder = Dense(hidden_dim_1, activation='relu')(decoder)
    decoder = Dense(encoding_dim, activation='relu')(decoder)
    decoder = Dense(input_dim, activation='linear')(decoder)
    autoencoder = Model(inputs=input_layer, outputs=decoder)
    autoencoder.summary()
    
    autoencoder.compile(metrics=['accuracy'], loss='mean_squared_error', optimizer='adam')
    write_model = ModelCheckpoint(filepath=r'C:\Users\bryan\Desktop\ae_dadta\model\ae_calssifier.h5', save_best_only=True, verbose=0)
    write_logs = TensorBoard(log_dir=r'C:\Users\bryan\Desktop\ae_dadta\logs', histogram_freq=0, write_graph=True, write_images=True)
    #history = autoencoder.fit(x_train_1, x_train_1,
    history = autoencoder.fit(x_train_0_x_rescaled, x_train_0_x_rescaled,
                            epochs=learning_epochs,
                            batch_size=batch_size,
                            #validation_data=(x_test_1, x_test_1),
                            validation_data=(x_valid_0_x_rescaled, x_valid_0_x_rescaled),
                            verbose=1,
                            callbacks=[write_model, write_logs]).history
    
    #test_x_predictions = autoencoder.predict(x_test)
    valid_x_predictions = autoencoder.predict(x_valid_x_rescaled)
    #mse = np.mean(np.power(x_test - test_x_predictions, 2), axis=1)
    mse = np.mean(np.power(x_valid_x_rescaled - valid_x_predictions, 2), axis=1)
    
    #error_df_test = pd.DataFrame({'Reconstruction_error': mse, 'True_class': y_test})
    #error_df_test = error_df_test.reset_index()
    error_df = pd.DataFrame({'Reconstruction_error': mse, 'True_class': x_valid[label]})
    false_pos_rate, true_pos_rate, thresholds = roc_curve(error_df['True_class'], error_df['Reconstruction_error'])
    threshold = np.mean(thresholds)
    threshold_fixed = float("{:0.4f}".format(threshold))
    roc_auc = auc(false_pos_rate, true_pos_rate,)
    print('MSE: ', mse)
    #print('Y val counts: ', y_test.value_counts())
    print('Threshold mean:', threshold)
    print('AUC: ', auc(false_pos_rate, true_pos_rate))

    if graph == 'loss':
        plt.plot(history['loss'])
        plt.plot(history['val_loss'])
        plt.title('model_loss')
        plt.ylabel('loss')
        plt.xlabel('epoch')
        plt.legend(['train', 'test'], loc='upper left')
        plt.show()
    elif graph == 'pre_call':
        precision_rt, recall_rt, threshold_rt = precision_recall_curve(error_df.True_class, error_df.Reconstruction_error)
        plt.plot(threshold_rt, precision_rt[1:], label='Precision', linewidth=5)
        plt.plot(threshold_rt, recall_rt[1:], label='Recall', linewidth=5)
        plt.title('Precision and recall for different threshold values')
        plt.xlabel('Threshold')
        plt.ylabel('Precision/Recall')
        plt.legend()
        plt.show()
    elif graph == 're_error':
        groups = error_df.groupby('True_class')
        fig, ax = plt.subplots()
        for name, group in groups:
            ax.plot(group.index, group.Reconstruction_error, marker='o', ms=3.5, linestyle='', label='Malware Estimation' if name == 1 else 'Benign Estimate')
        ax.hlines(threshold_fixed, ax.get_xlim()[0], ax.get_xlim()[1], colors='r', zorder=100, label='Threshold')
        ax.legend()
        plt.title('Reconstruction error for malicious/benign traffic')
        plt.ylabel('Reconstruction error')
        plt.xlabel('Data point index')
        plt.show()
    elif graph == 'heatmap':
        pred_y = [1 if e > threshold_fixed else 0 for e in error_df['Reconstruction_error'].values]
        conf_matrix = confusion_matrix(error_df['True_class'], pred_y)
        plt.figure(figsize=(8, 6))
        sns.heatmap(conf_matrix,
                    xticklabels=['Benign', 'Malware'],
                    yticklabels=['Benign', 'Malware'],
                    annot=True, fmt='d')
        plt.title('Confusion Matrix')
        plt.ylabel('True class')
        plt.xlabel('Predicted class')
        plt.show()
    elif graph == 'roc':
        plt.plot(false_pos_rate, true_pos_rate, linewidth=5, label='AUC = %0.3f'% roc_auc)
        plt.plot([0,1],[0,1], linewidth=5)
        plt.xlim([-0.01, 1])
        plt.ylim([0, 1.01])
        plt.legend(loc='lower right')
        plt.title('Reciever operating charactistic curve (ROC)')
        plt.ylabel('True Positive Rating')
        plt.xlabel('False Positive Rate')
        plt.show()
#    ae_input_features = len(data.columns)
#    round_one_hidden_units = 150
#    round_two_hidden_units = 100
#    round_three_hidden_units = 50
#    round_four_hidden_units = final_features

#    ae_inputs = tf.keras.Input(shape=(ae_input_features,))
#    ae_encoded = layers.Dense(round_one_hidden_units, activation='relu',
#                        activity_regularizer=regularizers.l1(10e-5))(ae_inputs)
#    ae_encoded = layers.Dense(round_two_hidden_units, activation='relu',
#                        activity_regularizer=regularizers.l1(10e-5))(ae_encoded)
#    ae_encoded = layers.Dense(round_three_hidden_units, activation='relu',
#                        activity_regularizer=regularizers.l1(10e-5))(ae_encoded)
#    ae_encoded = layers.Dense(round_four_hidden_units, activation='relu',
#                        activity_regularizer=regularizers.l1(10e-5))(ae_encoded)

#    encoder = Model(inputs=ae_inputs, outputs=ae_encoded)
#    encoded_data = pd.DataFrame(encoder.predict(data))
#    cols = []
#    for col in range(final_features):
#        col_name = 'feat_{}'.format(col)
#        cols.append(col_name)

#    encoded_data.columns = cols
#    if graph == 'pairwise':
#        sns.pairplot(encoded_data, kind='scatter', markers=['o', 's'], palette='Set2')
#    elif graph == 'heatmap':
#        correlation = encoded_data.corr()
#        sns.heatmap(correlation, annot=True, fmt='.2f', cmap = 'coolwarm')
#    plt.show()


#def load_input (csv_data_file):
csv_data_file = 'test_train_data-all.csv'
dataset = pd.read_csv(csv_data_file)
# Remove columns filled with all 0 value (these will be statistically insignifant and will cause
# issues when using correlation methods of analysis)
data_no_z_cols = dataset.loc[:, (dataset != 0).any(axis=0)]
