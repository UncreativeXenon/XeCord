#pragma once
#include <xtl.h>
#include "Vector3.h"

namespace Rage {
	namespace Native {
		class NativeCallContext {
		protected:
			PVOID m_pReturn;
			unsigned int m_uiArgCount;
			PVOID m_pArgList;
			unsigned int m_uiDataCount;
			Vector3* m_lpScriptVectors[4];
			BYTE m_lpVectorResults[0x10];
		public:
			void Reset();

			template<typename type>
			type GetArgument(int index);

			template<typename type>
			void SetArgument(int index, type value);

			template<typename type>
			void SetResult(int index, type value);
		};

		class NativeContext
			: public NativeCallContext {
		private:
			enum { MaxArgs = 32, ArgSize = 4 };
			BYTE m_szTempStack[MaxArgs * ArgSize];
		public:
			NativeContext();

			template <typename T>
			void Push(T a_nValue) {
				if (sizeof(T) > ArgSize)
					throw "Passed argument has an invalid size.";
				else if (sizeof(T) < ArgSize)
					memset(this->m_szTempStack + (this->m_uiArgCount * ArgSize), NULL, ArgSize);
				*(T*)(this->m_szTempStack + (this->m_uiArgCount * ArgSize)) = a_nValue;
				this->m_uiArgCount++;
			}

			template <typename T>
			T GetResult() {
				reinterpret_cast<void(*)(NativeContext*)>(0x83524878)(this);
				return *(T*)(this->m_szTempStack);
			}
		};

		struct NativeRegistration {
			NativeRegistration* pNextTable;
			DWORD dwFunctions[7];
			DWORD dwCount;
			DWORD dwHashes[7];
		};

		namespace Invoker {
			DWORD GetNativeHandler(DWORD a_dwHash);

			void Call(DWORD a_dwHash, NativeContext* a_nContext);

			template<typename R>
			static R Invoke(DWORD hash) {
				NativeContext l_lContext;
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1>
			static R Invoke(DWORD hash, T1 p1) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2>
			static R Invoke(DWORD hash, T1 p1, T2 p2) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21, T22 p22) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				l_lContext.Push(p22);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21, T22 p22, T23 p23) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				l_lContext.Push(p22);
				l_lContext.Push(p23);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23, typename T24>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21, T22 p22, T23 p23, T24 p24) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				l_lContext.Push(p22);
				l_lContext.Push(p23);
				l_lContext.Push(p24);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23, typename T24, typename T25>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21, T22 p22, T23 p23, T24 p24, T25 p25) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				l_lContext.Push(p22);
				l_lContext.Push(p23);
				l_lContext.Push(p24);
				l_lContext.Push(p25);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23, typename T24, typename T25, typename T26>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21, T22 p22, T23 p23, T24 p24, T25 p25, T26 p26) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				l_lContext.Push(p22);
				l_lContext.Push(p23);
				l_lContext.Push(p24);
				l_lContext.Push(p25);
				l_lContext.Push(p26);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23, typename T24, typename T25, typename T26, typename T27>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21, T22 p22, T23 p23, T24 p24, T25 p25, T26 p26, T27 p27) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				l_lContext.Push(p22);
				l_lContext.Push(p23);
				l_lContext.Push(p24);
				l_lContext.Push(p25);
				l_lContext.Push(p26);
				l_lContext.Push(p27);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}

			template<typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23, typename T24, typename T25, typename T26, typename T27, typename T28>
			static R Invoke(DWORD hash, T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11, T12 p12, T13 p13, T14 p14, T15 p15, T16 p16, T17 p17, T18 p18, T19 p19, T20 p20, T21 p21, T22 p22, T23 p23, T24 p24, T25 p25, T26 p26, T27 p27, T28 p28) {
				NativeContext l_lContext;
				l_lContext.Push(p1);
				l_lContext.Push(p2);
				l_lContext.Push(p3);
				l_lContext.Push(p4);
				l_lContext.Push(p5);
				l_lContext.Push(p6);
				l_lContext.Push(p7);
				l_lContext.Push(p8);
				l_lContext.Push(p9);
				l_lContext.Push(p10);
				l_lContext.Push(p11);
				l_lContext.Push(p12);
				l_lContext.Push(p13);
				l_lContext.Push(p14);
				l_lContext.Push(p15);
				l_lContext.Push(p16);
				l_lContext.Push(p17);
				l_lContext.Push(p18);
				l_lContext.Push(p19);
				l_lContext.Push(p20);
				l_lContext.Push(p21);
				l_lContext.Push(p22);
				l_lContext.Push(p23);
				l_lContext.Push(p24);
				l_lContext.Push(p25);
				l_lContext.Push(p26);
				l_lContext.Push(p27);
				l_lContext.Push(p28);
				Call(hash, &l_lContext);
				return l_lContext.GetResult<R>();
			}
		}
	}
}