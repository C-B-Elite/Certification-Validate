import C "mo:base/CertifiedData";
import T "mo:base/Text";

actor {

    public func set() : async(){
        C.set(T.encodeUtf8("test"))
    };

    public query func get() : async ?Blob{
        C.getCertificate()
    };

};
