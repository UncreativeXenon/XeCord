#include "Invoker.h"

namespace Rage {
	namespace Native {
		void NativeCallContext::Reset() {
			this->m_uiArgCount = NULL;
			this->m_uiDataCount = NULL;
		}

		template<typename type>
		type NativeCallContext::GetArgument(int index) {
			DWORD* args = (DWORD*)m_pArgList;
			return *(type*)&args[index];
		}

		template<typename type>
		void NativeCallContext::SetArgument(int index, type value) {
			DWORD* values = (DWORD*)m_pArgList;
			*(type*)&values[index] = value;
		}

		template<typename type>
		void NativeCallContext::SetResult(int index, type value) {
			DWORD* return_values = (DWORD*)m_pReturn;
			*(type*)&return_values[index] = value;
		}

		NativeContext::NativeContext() {
			this->m_pReturn = &this->m_szTempStack;
			this->m_pArgList = &this->m_szTempStack;
			this->m_uiArgCount = NULL;
			this->m_uiDataCount = NULL;
			memset(this->m_szTempStack, NULL, sizeof(this->m_szTempStack));
		}

		namespace Invoker {
			DWORD GetNativeHandler(DWORD a_dwHash) {
				if (a_dwHash == NULL) return NULL;
				NativeRegistration** pNativeRegistrationTable = (NativeRegistration**)(0x83DDCD08);
				NativeRegistration* table = pNativeRegistrationTable[a_dwHash & 0xFF];
				if (table) {
					for (; table; table = table->pNextTable)
						for (DWORD i = 0; i < table->dwCount; i++)
							if (a_dwHash == table->dwHashes[i])
								return table->dwFunctions[i];
				}
				return NULL;
			}

			void Call(DWORD a_dwHash, NativeContext* a_nContext) {
				if (DWORD l_dwHandler = GetNativeHandler(a_dwHash)) {
					((LPVOID(*)(NativeContext*))l_dwHandler)(a_nContext);
				}
			}
		}
	}
}