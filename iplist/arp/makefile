objects= get_ifi_info.o parse_hostnetworkmask.o getgateway.o get_printMAC.o wrapsock.o wrapunix.o error.o
#compiled-objects=error.o 
CFLAG=-g
ifdef DEBUG
  CFLAG+= -DDEBUG
endif
ifdef HASHCONFLICT
  CFLAG+=-DHASHCONFLICT
endif
ifdef 	MATCH
  CFLAG+=-DMATCHDEBUG
endif
ifdef 	VM
  CFLAG+=-DVMDEBUG
endif
CC=./agcc
WALL=-Wall

arpattack:$(objects) arpattack.c arpattack.h selfdefine.h unpifi.h jhash.h
	$(CC) $(CFLAG) $(WALL) arpattack.c $(objects) $(compiled-objects) -pthread -o arpattack
	
$(objects) : %.o : %.c unpifi.h
	$(CC) -c $(CFLAG) $<	-o $@ 
	
#清除中间生成的所有目标文件
.PHONY :clean
clean:
	#rm -f arpattack /bin/arpattack $(objects)

