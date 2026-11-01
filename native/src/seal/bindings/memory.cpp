// Licensed under the MIT license.

#include "seal/bindings/helpers.h"
#include <utility>

using namespace emscripten;
using namespace seal;
using namespace seal::bindings;

namespace
{
    // SEAL owns its active profile exclusively; JS handles share ownership of the selected profile.
    class SharedMMProf : public MMProf
    {
    public:
        explicit SharedMMProf(std::shared_ptr<MMProf> profile) : profile_(std::move(profile))
        {}

        MemoryPoolHandle get_pool(mm_prof_opt_t prof_opt) override
        {
            return profile_->get_pool(prof_opt);
        }

        const std::shared_ptr<MMProf> &profile() const noexcept
        {
            return profile_;
        }

    private:
        std::shared_ptr<MMProf> profile_;
    };

    std::shared_ptr<MMProf> switchProfile(const std::shared_ptr<MMProf> &profile)
    {
        if (!profile)
        {
            throw std::invalid_argument("mm_prof cannot be null");
        }

        auto previous = MemoryManager::SwitchProfile(std::make_unique<SharedMMProf>(profile));
        if (auto shared = dynamic_cast<SharedMMProf *>(previous.get()))
        {
            return shared->profile();
        }
        return std::shared_ptr<MMProf>(std::move(previous));
    }
} // namespace

EMSCRIPTEN_BINDINGS(seal_memory)
{
    class_<MemoryPoolHandle>("MemoryPoolHandle")
        .constructor<>()
        .class_function("Global", &MemoryPoolHandle::Global)
        .class_function("ThreadLocal", &MemoryPoolHandle::ThreadLocal)
        .class_function("New", &MemoryPoolHandle::New)
        .function(
            "isInitialized", optional_override([](const MemoryPoolHandle &self) { return static_cast<bool>(self); }))
        .function("poolCount", &MemoryPoolHandle::pool_count)
        .function("allocByteCount", &MemoryPoolHandle::alloc_byte_count)
        .function("useCount", &MemoryPoolHandle::use_count);

    class_<MMProf>("MMProf")
        .smart_ptr<std::shared_ptr<MMProf>>("shared_ptr<MMProf>")
        .function("getPool", &MMProf::get_pool);

    class_<MMProfGlobal, base<MMProf>>("MMProfGlobal")
        .smart_ptr_constructor("shared_ptr<MMProfGlobal>", &std::make_shared<MMProfGlobal>);

    class_<MMProfNew, base<MMProf>>("MMProfNew")
        .smart_ptr_constructor("shared_ptr<MMProfNew>", &std::make_shared<MMProfNew>);

    class_<MMProfFixed, base<MMProf>>("MMProfFixed")
        .smart_ptr_constructor("shared_ptr<MMProfFixed>", optional_override([](MemoryPoolHandle pool) {
                                   return std::make_shared<MMProfFixed>(std::move(pool));
                               }));

    class_<MMProfThreadLocal, base<MMProf>>("MMProfThreadLocal")
        .smart_ptr_constructor("shared_ptr<MMProfThreadLocal>", &std::make_shared<MMProfThreadLocal>);

    class_<MemoryManager>("MemoryManager")
        .class_function("GetPool", select_overload<MemoryPoolHandle()>(&MemoryManager::GetPool))
        .class_function("GetPool", select_overload<MemoryPoolHandle(mm_prof_opt_t)>(&MemoryManager::GetPool))
        .class_function("SwitchProfile", &switchProfile, nonnull<ret_val>());
}
