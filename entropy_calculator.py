import math
import time

class ddosDetection:
    pktCnt = 0
    sumEntropy = 0
    timer= time.time()

    def __init__(self):
        self.List_Dict = []
        self.sumEntropy_history=[]

    def addinfo(self, ADDINFO=None):
        self.pktCnt += 1
        self.List_Dict.append(ADDINFO)

    def calculateEntropy(self, calculate_permit=0):
        # calculate entropy when pkt cont reaches 100


        self.sumEntropy = 0
        #print("Window size of 100 pkts reached, calculate entropy")
        Set_List_Dict=list(set(self.List_Dict))

        for i in Set_List_Dict:
            #print(self.List_Dict.count(i), len(Set_List_Dict))
            un_i= self.List_Dict.count(i)/self.pktCnt
            self.sumEntropy +=(-un_i * math.log2(un_i))

        #print(self.sumEntropy)
        self.sumEntropy_history.append(self.sumEntropy)
        self.save_value()
        self.cleanUpValues()


    def save_value(self):
        if len(self.sumEntropy_history)>5:
            del self.sumEntropy_history[:1]
        return

    def cleanUpValues(self):
        #self.pktCnt = 50
        #del self.List_Dict[:50] # 50만 삭제하고 나머지 50은 다음 생성된 자료와 함깨 참조
        self.pktCnt = 0
        self.List_Dict=[] # 다 삭제하고 새로운 100개의 자료만 참조
        self.sumEntropy=0


