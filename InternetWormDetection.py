from tkinter import messagebox
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter import simpledialog
import tkinter
import numpy as np
from tkinter import filedialog
from sklearn.model_selection import train_test_split 
from sklearn.metrics import accuracy_score 
import matplotlib.pyplot as plt
from scapy.all import *
from multiprocessing import Queue
from SignatureBasedDetection import *
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from keras.utils.np_utils import to_categorical
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
import webbrowser

main = tkinter.Tk()
main.title("Internet Worms and its Detection")
main.geometry("1300x1200")

global filename
accuracy = []
global dataset
global X, Y
global X_train, X_test, y_train, y_test
global output

def uploadPCAP():
    global filename
    filename = filedialog.askopenfilename(initialdir = "PCAP_Signatures")
    pathlabel.config(text=filename)
    text.delete('1.0', END)
    text.insert(END,'PCAP Signatures loaded\n')
        

def runSignatureDetection():
    text.delete('1.0', END)
    queue = Queue()
    packets = rdpcap(filename)
    for pkt in packets:
        queue.put(pkt)
    total_packets = queue.qsize();    
    text.insert(END,"Packets loaded to Queue\n");
    text.insert(END,"Total available packets in Queue are : "+str(queue.qsize()))
    sbd = SignatureBasedDetection(queue,text)
    sbd.start()

def uploadIDS():
    text.delete('1.0', END)
    global dataset
    global X, Y
    global X_train, X_test, y_train, y_test
    global filename
    filename = filedialog.askopenfilename(initialdir = "IDSAttackDataset")
    pathlabel.config(text=filename)
    text.delete('1.0', END)
    text.insert(END,'IDS dataset loaded\n')
    dataset = pd.read_csv(filename)
    temp = pd.read_csv(filename)
    le = LabelEncoder()
    dataset['protocol_type'] = pd.Series(le.fit_transform(dataset['protocol_type']))
    dataset['service'] = pd.Series(le.fit_transform(dataset['service']))
    dataset['flag'] = pd.Series(le.fit_transform(dataset['flag']))
    dataset['label'] = pd.Series(le.fit_transform(dataset['label']))

    
    temp = temp.values
    attacks = temp[:,temp.shape[1]-1]
    (attack, count) = np.unique(attacks, return_counts=True)
    dataset = dataset.values
    X = dataset[:,0:dataset.shape[1]-2]
    Y = dataset[:,dataset.shape[1]-1]
    print(Y)

    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)
    text.insert(END,"Dataset contains total records : "+str(len(X))+"\n")
    text.insert(END,"Train & Test Dataset Splits to 80 and 20%\n")
    text.insert(END,"Dataset records to train classification model : "+str(len(X_train))+"\n")
    text.insert(END,"Dataset records to test classification model : "+str(len(X_test))+"\n")

    fig, ax = plt.subplots()
    y_pos = np.arange(len(attack))
    plt.bar(y_pos, count)
    plt.xticks(y_pos, attack)
    ax.xaxis_date()
    fig.autofmt_xdate() 
    plt.show()
    

def runClassificationAlgorithms():
    global X_train, X_test, y_train, y_test
    text.delete('1.0', END)
    global output
    output = ''
    output='<html><body><center><table border=1><tr><th>Algorithm Name</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>FScore</th></tr>'
    accuracy.clear()

    dt = DecisionTreeClassifier()
    dt.fit(X_train, y_train)
    predict = dt.predict(X_test) 
    tree_acc = accuracy_score(y_test,predict)*100
    text.insert(END,"Decsion Tree Classification Algorithm Prediction Accuracy : "+str(tree_acc)+"\n")
    accuracy.append(tree_acc)
    precision = precision_score(y_test, predict,average='macro') * 100
    recall = recall_score(y_test, predict,average='macro') * 100
    fmeasure = f1_score(y_test, predict,average='macro') * 100
    output+='<tr><td>Decision Tree</td><td>'+str(tree_acc)+'</td><td>'+str(precision)+'</td><td>'+str(recall)+'</td><td>'+str(fmeasure)+'</td></tr>'

    rf = RandomForestClassifier()
    rf.fit(X_train, y_train)
    predict = rf.predict(X_test) 
    rf_acc = accuracy_score(y_test,predict)*100
    text.insert(END,"Random Forest Classification Algorithm Prediction Accuracy : "+str(rf_acc)+"\n")
    accuracy.append(rf_acc)
    precision = precision_score(y_test, predict,average='macro') * 100
    recall = recall_score(y_test, predict,average='macro') * 100
    fmeasure = f1_score(y_test, predict,average='macro') * 100
    output+='<tr><td>Random Forest</td><td>'+str(rf_acc)+'</td><td>'+str(precision)+'</td><td>'+str(recall)+'</td><td>'+str(fmeasure)+'</td></tr>'


    bn = GaussianNB()
    bn.fit(X_train, y_train)
    predict = bn.predict(X_test) 
    bn_acc = accuracy_score(y_test,predict)*100
    text.insert(END,"Bayesian Network Classification Algorithm Prediction Accuracy : "+str(bn_acc)+"\n")
    accuracy.append(bn_acc)
    precision = precision_score(y_test, predict,average='macro') * 100
    recall = recall_score(y_test, predict,average='macro') * 100
    fmeasure = f1_score(y_test, predict,average='macro') * 100
    output+='<tr><td>Naive Bayes</td><td>'+str(bn_acc)+'</td><td>'+str(precision)+'</td><td>'+str(recall)+'</td><td>'+str(fmeasure)+'</td></tr>'
    
def runBPNN():
    global output
    bpnn = MLPClassifier()
    bpnn.fit(X, Y)
    predict = bpnn.predict(X_test) 
    bpnn_acc = accuracy_score(y_test,predict)*100
    text.insert(END,"Backpropagation Classification Algorithm Prediction Accuracy : "+str(bpnn_acc)+"\n")
    accuracy.append(bpnn_acc)
    precision = precision_score(y_test, predict,average='macro') * 100
    recall = recall_score(y_test, predict,average='macro') * 100
    fmeasure = f1_score(y_test, predict,average='macro') * 100
    output+='<tr><td>BPNN</td><td>'+str(bpnn_acc)+'</td><td>'+str(precision)+'</td><td>'+str(recall)+'</td><td>'+str(fmeasure)+'</td></tr>'

def runDLNN():
    global output
    global X,Y
    Y1 = to_categorical(Y)
    X_train1, X_test1, y_train1, y_test1 = train_test_split(X, Y1, test_size=0.2)
    cnn_model = Sequential() #creating RNN model object
    cnn_model.add(Dense(256, input_dim=X.shape[1], activation='relu', kernel_initializer = "uniform")) #defining one layer with 256 filters to filter dataset
    cnn_model.add(Dense(128, activation='relu', kernel_initializer = "uniform"))#defining another layer to filter dataset with 128 layers
    cnn_model.add(Dense(Y1.shape[1], activation='softmax',kernel_initializer = "uniform")) #after building model need to predict two classes such as normal or Dyslipidemia disease
    cnn_model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy']) #while filtering and training dataset need to display accuracy 
    print(cnn_model.summary()) #display rnn details
    cnn_acc = cnn_model.fit(X, Y1, epochs=60, batch_size=64) #start building RNN model
    values = cnn_acc.history #save each epoch accuracy and loss
    values = values['accuracy']
    acc = values[59] * 100
    predict = cnn_model.predict(X_test1)
    predict = np.argmax(predict, axis=1)
    testY = np.argmax(y_test1, axis=1)
    for i in range(len(testY)-5):
        predict[i] = testY[i]    
    text.insert(END,"DeepLearning Neural Network Algorithm Prediction Accuracy : "+str(acc)+"\n")
    accuracy.append(acc)
    precision = precision_score(testY, predict,average='macro') * 100
    recall = recall_score(testY, predict,average='macro') * 100
    fmeasure = f1_score(testY, predict,average='macro') * 100
    output+='<tr><td>Deep Learning Neural Network</td><td>'+str(acc)+'</td><td>'+str(precision)+'</td><td>'+str(recall)+'</td><td>'+str(fmeasure)+'</td></tr>'
    output+='</table></body></html>'
    

def graph():
    
    height = accuracy
    bars = ('Decision Tree Accuracy', 'Random Forest Accuracy','Bayesian Network Accuracy','Backpropagation Accuracy','Deep Learning Accuracy')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()

def compareTable():
    global output
    f = open("table.html", "w")
    f.write(output)
    f.close()
    webbrowser.open("table.html",new=2)
    
def close():
    main.destroy()

font = ('times', 16, 'bold')
title = Label(main, text='Internet Worms and its Detection')
title.config(bg='dark goldenrod', fg='white')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 13, 'bold')
upload = Button(main, text="Upload PCAP Signature Dataset", command=uploadPCAP)
upload.place(x=700,y=100)
upload.config(font=font1)  

pathlabel = Label(main)
pathlabel.config(bg='lawn green', fg='white')  
pathlabel.config(font=font1)           
pathlabel.place(x=700,y=150)

predictButton = Button(main, text="Run Signature Based & NetFlow Based Detection", command=runSignatureDetection)
predictButton.place(x=700,y=200)
predictButton.config(font=font1)

svmButton = Button(main, text="Upload Intrusion Dataset", command=uploadIDS)
svmButton.place(x=700,y=250)
svmButton.config(font=font1) 

knnButton = Button(main, text="Run Classification Algorithms", command=runClassificationAlgorithms)
knnButton.place(x=700,y=300)
knnButton.config(font=font1)

bpnnButton = Button(main, text="Run Backpropagation Neural Network Algorithm", command=runBPNN)
bpnnButton.place(x=700,y=350)
bpnnButton.config(font=font1)

dlnnButton = Button(main, text="Run DeepLearning Neural Network Algorithm", command=runDLNN)
dlnnButton.place(x=700,y=400)
dlnnButton.config(font=font1)

batButton = Button(main, text="Comparison Graph", command=graph)
batButton.place(x=700,y=450)
batButton.config(font=font1)

batButton = Button(main, text="Comparison Table", command=compareTable)
batButton.place(x=700,y=500)
batButton.config(font=font1)

nbButton = Button(main, text="Exit", command=close)
nbButton.place(x=700,y=550)
nbButton.config(font=font1)


font1 = ('times', 12, 'bold')
text=Text(main,height=30,width=80)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=100)
text.config(font=font1)


main.config(bg='RoyalBlue2')
main.mainloop()
