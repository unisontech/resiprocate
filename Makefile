# $Id: Makefile,v 1.34 2002/09/22 18:08:36 dabryan Exp $

# must have ARCH set
ARCH = i686

PROG = sipstack

SRC =	\
	Condition.cxx \
	Data.cxx \
	Executive.cxx \
	FloatSubComponent.cxx \
	HeaderFieldValue.cxx \
	HeaderFieldValueList.cxx \
	HeaderTypes.cxx \
	IntSubComponent.cxx \
	Lock.cxx \
	Log.cxx \
	Logger.cxx \
	Message.cxx \
	MethodTypes.cxx \
	Mutex.cxx \
	ParserCategories.cxx \
	Preparse.cxx \
	SipMessage.cxx \
	SipStack.cxx \
	StringSubComponent.cxx \
	SubComponent.cxx \
	SubComponentList.cxx \
	Subsystem.cxx \
	Symbols.cxx \
	Timer.cxx \
	TimerMessage.cxx \
	TimerQueue.cxx \
	TransactionState.cxx \
	TransactionMap.cxx \
	Transport.cxx \
	TransportSelector.cxx \
	UdpTransport.cxx \
	UnknownSubComponent.cxx \




OSRC =   *.hxx Makefile


#CXXFLAGS += -pg
#LDFLAGS  += -pg
#CXXFLAGS += -Weffc++
# optimize does not work with gcc 2.8 compiler
#CXXFLAGS += -O5 -DNDEBUG
CXXFLAGS += -O -g
#CXXFLAGS += -g
LDFLAGS  += 
CXXFLAGS += -I. -I../. -I../../. -MD -Wall $(CXXDEBUG)
LDLIBS   += 

ifeq ($(ARCH),i686)
CXXFLAGS += -mcpu=i686 -march=i686
endif

OBJ = obj.$(ARCH)
BIN = bin.$(ARCH)

OBJS = $(patsubst %.cxx,$(OBJ)/%.o,$(SRC))

# OK THE REST OF THE FILE IS NOT REALLY MEANT TO BE MODIFIED


#define the rules

all: $(OBJ) $(BIN) $(BIN)/libSipStack.a

doc: html html/HIER.html html/sipStack.html fsm.pdf

clean:
	-rm -f *.rpo core *~ \#* .make* *.a *.d
	-rm -rf html
	-rm obj.*/*.[od] bin.*/$(PROG) 

backup:
	tar cvf - $(SRC) $(OSRC) | gzip > `date +"backup_$(PROG)%b%d.tgz"`

$(BIN):
	- mkdir $(BIN)

$(OBJ):
	- mkdir $(OBJ)

html:
	- mkdir html

html/HIER.html: *hxx
	doc++ -B noBanner -p -d html *.hxx

html/sipStack.html: *.cxx *.hxx 
	cvs2html -a -k -o html

fsm.dot: Preparse.cxx dot.awk
	awk -f dot.awk Preparse.cxx > fsm.dot

%.pdf: %.ps
	ps2pdf13 $<

%.ps: %.dot
	dot -Tps -o$@ $<

$(OBJ)/%.o: %.cxx
	$(CXX) $(CXXFLAGS) -c -o $@ $<
	@[ -f $(@F:.o=.d) ] && mv $(@F:.o=.d) $(@:.o=_tmp.d) || \
		mv $(@:.o=.d) $(@:.o=_tmp.d)
	@sed -e "s/^$(@F)/$(@D)\/$(@F)/" < $(@:.o=_tmp.d) > $(@:.o=.d)
	@rm  $(@:.o=_tmp.d)


%.S: %.cxx
	$(CXX) $(CXXFLAGS)  -fverbose-asm -g -Wa,-ahln -c \
		-o /tmp/cjJunk.o $< > $@

$(BIN)/libSipStack.a: $(OBJS)
	ar $(ARFLAGS) $@ $^



testSubComponentList:  $(OBJS) $(OBJ)/testSubComponentList.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

testUdp:  $(OBJS) $(OBJ)/testUdp.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

testPreparse: $(OBJ)/Preparse.o $(OBJ)/testPreparse.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

testSipStack1:  $(OBJS) $(OBJ)/testSipStack1.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

testSipMessage:  $(OBJS) $(OBJ)/testSipMessage.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

convertStringToInt:  $(OBJS) $(OBJ)/convertStringToInt.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)


-include $(OBJ)/*.d
