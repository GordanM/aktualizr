/*
* This file was generated by the CommonAPI Generators.
* Used org.genivi.commonapi.core 3.1.5.v201601121427.
* Used org.franca.core 0.9.1.201412191134.
*
* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
* If a copy of the MPL was not distributed with this file, You can obtain one at
* http://mozilla.org/MPL/2.0/.
*/
/**
 * description: Software Loading Manager interfaace
 */
#ifndef V1_ORG_GENIVI_Software_Loading_Manager_STUB_HPP_
#define V1_ORG_GENIVI_Software_Loading_Manager_STUB_HPP_

#include <functional>




#include <v1/org/genivi/SoftwareLoadingManager.hpp>

#if !defined (COMMONAPI_INTERNAL_COMPILATION)
#define COMMONAPI_INTERNAL_COMPILATION
#endif

#include <CommonAPI/Deployment.hpp>
#include <CommonAPI/InputStream.hpp>
#include <CommonAPI/OutputStream.hpp>
#include <CommonAPI/Struct.hpp>
#include <cstdint>
#include <string>
#include <vector>

#include <CommonAPI/Stub.hpp>

#undef COMMONAPI_INTERNAL_COMPILATION

namespace v1 {
namespace org {
namespace genivi {

/**
 * Receives messages from remote and handles all dispatching of deserialized calls
 * to a stub for the service SoftwareLoadingManager. Also provides means to send broadcasts
 * and attribute-changed-notifications of observable attributes as defined by this service.
 * An application developer should not need to bother with this class.
 */
class SoftwareLoadingManagerStubAdapter
    : public virtual CommonAPI::StubAdapter, 
      public virtual SoftwareLoadingManager {
 public:



    virtual void deactivateManagedInstances() = 0;
protected:
    /**
     * Defines properties for storing the ClientIds of clients / proxies that have
     * subscribed to the selective broadcasts
     */
};

/**
 * Defines the necessary callbacks to handle remote set events related to the attributes
 * defined in the IDL description for SoftwareLoadingManager.
 * For each attribute two callbacks are defined:
 * - a verification callback that allows to verify the requested value and to prevent setting
 *   e.g. an invalid value ("onRemoteSet<AttributeName>").
 * - an action callback to do local work after the attribute value has been changed
 *   ("onRemote<AttributeName>Changed").
 *
 * This class and the one below are the ones an application developer needs to have
 * a look at if he wants to implement a service.
 */
class SoftwareLoadingManagerStubRemoteEvent
{
public:
    virtual ~SoftwareLoadingManagerStubRemoteEvent() { }

};

/**
 * Defines the interface that must be implemented by any class that should provide
 * the service SoftwareLoadingManager to remote clients.
 * This class and the one above are the ones an application developer needs to have
 * a look at if he wants to implement a service.
 */
class SoftwareLoadingManagerStub
    : public virtual CommonAPI::Stub<SoftwareLoadingManagerStubAdapter, SoftwareLoadingManagerStubRemoteEvent>
{
public:
    typedef std::function<void ()>updateAvailableReply_t;
    typedef std::function<void ()>downloadCompleteReply_t;
    typedef std::function<void ()>updateConfirmationReply_t;
    typedef std::function<void ()>abortDownloadReply_t;
    typedef std::function<void ()>operationResultReply_t;
    typedef std::function<void (std::vector<SoftwareLoadingManager::InstalledPackage> _installedPackages, std::vector<SoftwareLoadingManager::InstalledFirmware> _installedFirmware)>getInstalledSoftwareReply_t;

    virtual ~SoftwareLoadingManagerStub() {}
    virtual const CommonAPI::Version& getInterfaceVersion(std::shared_ptr<CommonAPI::ClientId> clientId) = 0;


    /**
     * description: Message, sent by SC or DiagTollMgr to SWLM, to inform that a new
        package is
     *   available for download.
    	This is a fire and forget message. If the update is
     *   to be downloaded,
    	org.genivi.swm.sc.initiate_download() will be called.
     */
    /// This is the method that will be called on remote calls on the method updateAvailable.
    virtual void updateAvailable(const std::shared_ptr<CommonAPI::ClientId> _client, std::string _updateId, std::string _description, std::string _signature, bool _requestConfirmation, uint64_t _size, std::string _name, updateAvailableReply_t _reply) = 0;
    /**
     * description: Message, sent by SC to SWLM, to indicate
    	that a download previously initiated
     *   by a
     */
    /// This is the method that will be called on remote calls on the method downloadComplete.
    virtual void downloadComplete(const std::shared_ptr<CommonAPI::ClientId> _client, std::string _updateImage, std::string _signature, downloadCompleteReply_t _reply) = 0;
    /**
     * description: Message, sent by HMI to SWLM to specify
    	if a user confirmed or declined an
     *   update notified to HMI through a
    	org.genivi.swm.hmi.updateNotificataion()
     *   call.
     */
    /// This is the method that will be called on remote calls on the method updateConfirmation.
    virtual void updateConfirmation(const std::shared_ptr<CommonAPI::ClientId> _client, uint32_t _updateId, bool _approved, updateConfirmationReply_t _reply) = 0;
    /**
     * description: Abort a download in progress.
    	Invoked by HMI in response to SWLM in response
     *   to a user abort.
    	Will be forwarded by SWLM to SC in order to complete the
     *   abort.
     */
    /// This is the method that will be called on remote calls on the method abortDownload.
    virtual void abortDownload(const std::shared_ptr<CommonAPI::ClientId> _client, std::string _updateId, abortDownloadReply_t _reply) = 0;
    /**
     * description: Message, sent by other components to SWLM to report the result
    	of an update
     *   operation initiated by a previous
    	call to one of the following
     *   methods:
    	org.genivi.swm.packmgr.installPackage()
    	org.genivi.swm.packmgr.upgra
     *  dePackage()
    	org.genivi.swm.packmgr.removePackage()
    	org.genivi.swm.partmgr.crea
     *  teDiskPartition()
    	org.genivi.swm.packmgr.deleteDiskPartition()
    	org.genivi.swm.
     *  packmgr.resizeDiskPartition()
    	org.genivi.swm.packmgr.writeDiskPartition()
    	org.
     *  genivi.swm.packmgr.patchDiskPartition()
    	org.genivi.swm.ml.flashModuleFirmware()
     */
    /// This is the method that will be called on remote calls on the method operationResult.
    virtual void operationResult(const std::shared_ptr<CommonAPI::ClientId> _client, uint32_t _transactionId, SoftwareLoadingManager::SWMResult _resultCode, std::string _resultText, operationResultReply_t _reply) = 0;
    /**
     * description: Message, sent by CEDM or SC to SWLM to retrieve a
    	list of installed software
     *   packages and/or module
    	firmware versions.
     */
    /// This is the method that will be called on remote calls on the method getInstalledSoftware.
    virtual void getInstalledSoftware(const std::shared_ptr<CommonAPI::ClientId> _client, bool _includePackages, bool _includeModuleFirmware, getInstalledSoftwareReply_t _reply) = 0;

    using CommonAPI::Stub<SoftwareLoadingManagerStubAdapter, SoftwareLoadingManagerStubRemoteEvent>::initStubAdapter;
    typedef CommonAPI::Stub<SoftwareLoadingManagerStubAdapter, SoftwareLoadingManagerStubRemoteEvent>::StubAdapterType StubAdapterType;
    typedef CommonAPI::Stub<SoftwareLoadingManagerStubAdapter, SoftwareLoadingManagerStubRemoteEvent>::RemoteEventHandlerType RemoteEventHandlerType;
    typedef SoftwareLoadingManagerStubRemoteEvent RemoteEventType;
    typedef SoftwareLoadingManager StubInterface;
};

} // namespace genivi
} // namespace org
} // namespace v1


// Compatibility
namespace v1_0 = v1;

#endif // V1_ORG_GENIVI_Software_Loading_Manager_STUB_HPP_