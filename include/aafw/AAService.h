/**
 * Autogenerated by Thrift Compiler (0.9.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef AAService_H
#define AAService_H

#include <thrift/TDispatchProcessor.h>
#include "aafw/aafw_types.h"

namespace aafw {

class AAServiceIf {
 public:
  virtual ~AAServiceIf() {}
  virtual void request(ACResp& _return, const ACReq& req) = 0;
};

class AAServiceIfFactory {
 public:
  typedef AAServiceIf Handler;

  virtual ~AAServiceIfFactory() {}

  virtual AAServiceIf* getHandler(const ::apache::thrift::TConnectionInfo& connInfo) = 0;
  virtual void releaseHandler(AAServiceIf* /* handler */) = 0;
};

class AAServiceIfSingletonFactory : virtual public AAServiceIfFactory {
 public:
  AAServiceIfSingletonFactory(const boost::shared_ptr<AAServiceIf>& iface) : iface_(iface) {}
  virtual ~AAServiceIfSingletonFactory() {}

  virtual AAServiceIf* getHandler(const ::apache::thrift::TConnectionInfo&) {
    return iface_.get();
  }
  virtual void releaseHandler(AAServiceIf* /* handler */) {}

 protected:
  boost::shared_ptr<AAServiceIf> iface_;
};

class AAServiceNull : virtual public AAServiceIf {
 public:
  virtual ~AAServiceNull() {}
  void request(ACResp& /* _return */, const ACReq& /* req */) {
    return;
  }
};

typedef struct _AAService_request_args__isset {
  _AAService_request_args__isset() : req(false) {}
  bool req;
} _AAService_request_args__isset;

class AAService_request_args {
 public:

  AAService_request_args() {
  }

  virtual ~AAService_request_args() throw() {}

  ACReq req;

  _AAService_request_args__isset __isset;

  void __set_req(const ACReq& val) {
    req = val;
  }

  bool operator == (const AAService_request_args & rhs) const
  {
    if (!(req == rhs.req))
      return false;
    return true;
  }
  bool operator != (const AAService_request_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const AAService_request_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class AAService_request_pargs {
 public:


  virtual ~AAService_request_pargs() throw() {}

  const ACReq* req;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _AAService_request_result__isset {
  _AAService_request_result__isset() : success(false) {}
  bool success;
} _AAService_request_result__isset;

class AAService_request_result {
 public:

  AAService_request_result() {
  }

  virtual ~AAService_request_result() throw() {}

  ACResp success;

  _AAService_request_result__isset __isset;

  void __set_success(const ACResp& val) {
    success = val;
  }

  bool operator == (const AAService_request_result & rhs) const
  {
    if (!(success == rhs.success))
      return false;
    return true;
  }
  bool operator != (const AAService_request_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const AAService_request_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _AAService_request_presult__isset {
  _AAService_request_presult__isset() : success(false) {}
  bool success;
} _AAService_request_presult__isset;

class AAService_request_presult {
 public:


  virtual ~AAService_request_presult() throw() {}

  ACResp* success;

  _AAService_request_presult__isset __isset;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

class AAServiceClient : virtual public AAServiceIf {
 public:
  AAServiceClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) :
    piprot_(prot),
    poprot_(prot) {
    iprot_ = prot.get();
    oprot_ = prot.get();
  }
  AAServiceClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, boost::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) :
    piprot_(iprot),
    poprot_(oprot) {
    iprot_ = iprot.get();
    oprot_ = oprot.get();
  }
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getInputProtocol() {
    return piprot_;
  }
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> getOutputProtocol() {
    return poprot_;
  }
  void request(ACResp& _return, const ACReq& req);
  void send_request(const ACReq& req);
  void recv_request(ACResp& _return);
 protected:
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> piprot_;
  boost::shared_ptr< ::apache::thrift::protocol::TProtocol> poprot_;
  ::apache::thrift::protocol::TProtocol* iprot_;
  ::apache::thrift::protocol::TProtocol* oprot_;
};

class AAServiceProcessor : public ::apache::thrift::TDispatchProcessor {
 protected:
  boost::shared_ptr<AAServiceIf> iface_;
  virtual bool dispatchCall(::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, const std::string& fname, int32_t seqid, void* callContext);
 private:
  typedef  void (AAServiceProcessor::*ProcessFunction)(int32_t, ::apache::thrift::protocol::TProtocol*, ::apache::thrift::protocol::TProtocol*, void*);
  typedef std::map<std::string, ProcessFunction> ProcessMap;
  ProcessMap processMap_;
  void process_request(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
 public:
  AAServiceProcessor(boost::shared_ptr<AAServiceIf> iface) :
    iface_(iface) {
    processMap_["request"] = &AAServiceProcessor::process_request;
  }

  virtual ~AAServiceProcessor() {}
};

class AAServiceProcessorFactory : public ::apache::thrift::TProcessorFactory {
 public:
  AAServiceProcessorFactory(const ::boost::shared_ptr< AAServiceIfFactory >& handlerFactory) :
      handlerFactory_(handlerFactory) {}

  ::boost::shared_ptr< ::apache::thrift::TProcessor > getProcessor(const ::apache::thrift::TConnectionInfo& connInfo);

 protected:
  ::boost::shared_ptr< AAServiceIfFactory > handlerFactory_;
};

class AAServiceMultiface : virtual public AAServiceIf {
 public:
  AAServiceMultiface(std::vector<boost::shared_ptr<AAServiceIf> >& ifaces) : ifaces_(ifaces) {
  }
  virtual ~AAServiceMultiface() {}
 protected:
  std::vector<boost::shared_ptr<AAServiceIf> > ifaces_;
  AAServiceMultiface() {}
  void add(boost::shared_ptr<AAServiceIf> iface) {
    ifaces_.push_back(iface);
  }
 public:
  void request(ACResp& _return, const ACReq& req) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->request(_return, req);
    }
    ifaces_[i]->request(_return, req);
    return;
  }

};

} // namespace

#endif
