#include <Windows.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <winber.h>
#include <LM.h>
#include <authz.h>

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <algorithm>
#include <functional>
#include <iostream>
#include <format>
#include <sstream>
#include <regex>
#include <iomanip>
#include <cwctype>

#pragma comment(lib, "Activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "Authz.lib")

#pragma comment(lib, "NetApi32.lib")
#pragma comment(lib, "Wldap32.lib")
//****************************************************************************************************
using _ldap_msgfree = decltype([](LDAPMessage* value){ ldap_msgfree(value); });
using _ldap_memfree = decltype([](PWCHAR value){ ldap_memfreeW(value); });
using _ldap_value_free = decltype([](PWCHAR* value){ ldap_value_freeW(value); });
using _ldap_value_free_len = decltype([](berval** value){ ldap_value_free_len(value); });

struct _ldap_search_abandon_page
{
	PLDAP _ldap_handle;
	void operator()(PLDAPSearch value) const noexcept { ldap_search_abandon_page(_ldap_handle, value); };
};

using _NetApiBufferFree = decltype([](PDOMAIN_CONTROLLER_INFOW value){ NetApiBufferFree(value); });
using _ber_free = decltype([](BerElement* value){ ber_free(value, 0); });
using _ber_free_1 = decltype([](BerElement* value){ ber_free(value, 1); });
using _ber_bvfree = decltype([](berval* value){ ber_bvfree(value); });
//****************************************************************************************************
std::shared_ptr<LDAP> ldap_init_connection()
{
	#pragma region Initialize connection with LDAP server
	#pragma region Get information about LDAP server name
	std::unique_ptr<DOMAIN_CONTROLLER_INFOW, _NetApiBufferFree> inflow;

	auto result = DsGetDcNameW(nullptr, nullptr, nullptr, nullptr, DS_ONLY_LDAP_NEEDED | DS_RETURN_DNS_NAME, std::out_ptr(inflow));
	if(nullptr == inflow)
		throw std::exception("Error in DsGetDcNameW");
	#pragma endregion

	#pragma region Initialize TLS connection with LDAP server
	std::shared_ptr<LDAP> ldap_handle{ ldap_initW(&inflow->DomainControllerName[2], LDAP_PORT), [](LDAP* value){ ldap_unbind(value); } };
	if(nullptr == ldap_handle)
		throw std::exception("Error during ldap_sslinit");

	#pragma region Set additional options for LDAP connection
	if(ldap_set_optionW(ldap_handle.get(), LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON))
		throw std::exception("Cannot set LDAP_OPT_AREC_EXCLUSIVE option");

	ULONG ldap_version = LDAP_VERSION3;
	if(ldap_set_optionW(ldap_handle.get(), LDAP_OPT_PROTOCOL_VERSION, &ldap_version))
		throw std::exception("Cannot set LDAP_OPT_PROTOCOL_VERSION option");
	#pragma endregion

	if(ldap_bind_sW(ldap_handle.get(), nullptr, nullptr, LDAP_AUTH_NEGOTIATE))
		throw std::exception("Cannot bind to LDAP");
	#pragma endregion
	#pragma endregion

	return ldap_handle;
}
//****************************************************************************************************
std::map<std::wstring, std::wstring> ldap_search_contexts(std::shared_ptr<LDAP> handle)
{
	#pragma region Initial variables
	std::map<std::wstring, std::wstring> result;
	#pragma endregion

	#pragma region Search for all namingContexts
	const wchar_t* namingContexts[] = {
		L"namingContexts",
		nullptr
	};

	std::unique_ptr<LDAPMessage, _ldap_msgfree> namingContextsMessage;
	if(ldap_search_sW(handle.get(), (wchar_t*)L"", LDAP_SCOPE_BASE, (wchar_t*)L"(objectCategory=*)", (wchar_t**)namingContexts, FALSE, std::out_ptr(namingContextsMessage)))
		throw std::exception("Cannot make ldap_search_s");
	#pragma endregion

	#pragma region Get values from the search
	auto namingContextsEntry = ldap_first_entry(handle.get(), namingContextsMessage.get());
	if(nullptr == namingContextsEntry)
		throw std::exception("No entries in result search");

	std::unique_ptr<BerElement, _ber_free> namingContextsBER;

	std::unique_ptr<wchar_t, _ldap_memfree> namingContextsAttribute{ ldap_first_attributeW(handle.get(), namingContextsEntry, std::out_ptr(namingContextsBER)) };
	if(nullptr == namingContextsAttribute)
		throw std::exception("Cannot get first attributes for the search");

	std::unique_ptr<wchar_t* [], _ldap_value_free> namingContextsValues{ ldap_get_valuesW(handle.get(), namingContextsEntry, namingContextsAttribute.get()) };
	if(nullptr == namingContextsValues)
		throw std::exception("Cannot get values from attribute");

	auto namingContextsValuesCount = ldap_count_valuesW(namingContextsValues.get());
	#pragma endregion

	#pragma region Find correct DN names for necessary namespaces
	std::wstring config_ns;
	std::wstring schema_ns;

	for(ULONG i = 0; i < namingContextsValuesCount; i++)
	{
		std::wstring value{ namingContextsValues[i] };
		std::transform(value.begin(), value.end(), value.begin(), std::towlower);

		if(value.find(L"cn=configuration") == 0)
			config_ns = std::move(value);
		else
		{
			if(value.find(L"cn=schema") == 0)
				schema_ns = std::move(value);
			else
				result[L""] = value;
		}

		if(config_ns.size() && schema_ns.size())
			break;
	}

	if(!(config_ns.size() && schema_ns.size()))
		throw std::exception("Cannot find Configuration or Schema contexts");
	#pragma endregion

	#pragma region Set necessary values to result map
	result[L"config"] = config_ns;
	result[L"schema"] = schema_ns;
	#pragma endregion

	return result;
}
//****************************************************************************************************
std::wstring string_to_wstring(std::string value)
{
	size_t size = value.size() + 1;
	std::wstring result(size, L'\0');

	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, result.data(), size, value.data(), _TRUNCATE);

	return result;
}
//****************************************************************************************************
void ldap_search_element_ext(
	std::shared_ptr<LDAP> handle,
	std::wstring dn,
	std::vector<std::wstring> attributes,
	std::function<void(std::shared_ptr<LDAP>, LDAPMessage*)> func,
	std::wstring_view filter = L"objectClass=*"
)
{
	#pragma region Initial variables
	unsigned long errorCode = LDAP_SUCCESS;

	SECURITY_INFORMATION info =
		OWNER_SECURITY_INFORMATION
		| GROUP_SECURITY_INFORMATION
		| DACL_SECURITY_INFORMATION
		//| SACL_SECURITY_INFORMATION
		//| LABEL_SECURITY_INFORMATION
		//| ATTRIBUTE_SECURITY_INFORMATION
		//| SCOPE_SECURITY_INFORMATION
		//| PROCESS_TRUST_LABEL_SECURITY_INFORMATION
		//| ACCESS_FILTER_SECURITY_INFORMATION
		//| BACKUP_SECURITY_INFORMATION
		//| PROTECTED_DACL_SECURITY_INFORMATION
		//| PROTECTED_SACL_SECURITY_INFORMATION
		//| UNPROTECTED_DACL_SECURITY_INFORMATION
		//| UNPROTECTED_SACL_SECURITY_INFORMATION
		;

	std::unique_ptr <berval, _ber_bvfree> pBerVal;
	std::unique_ptr<BerElement, _ber_free_1> pBerElmt{ ber_alloc_t(LBER_USE_DER) };
	ber_printf(pBerElmt.get(), (PSTR)"{i}", info);
	ber_flatten(pBerElmt.get(), std::out_ptr(pBerVal));

	LDAPControlW infoControl =
	{
		(PWCHAR)L"1.2.840.113556.1.4.801", // LDAP_SERVER_SD_FLAGS_OID_W,
		*pBerVal,
		TRUE
	};

	PLDAPControlW ServerControls[2] =
	{
		&infoControl,
		nullptr
	};
	#pragma endregion

	#pragma region Create correct values for LDAP search
	std::vector<wchar_t*> schemaAttrs;
	std::for_each(attributes.begin(), attributes.end(), [&schemaAttrs](std::wstring& value){ schemaAttrs.push_back(value.data()); });
	schemaAttrs.push_back(nullptr);
	#pragma endregion

	#pragma region Perform LDAP search
	std::unique_ptr<LDAPMessage, _ldap_msgfree> search_message;

	errorCode = ldap_search_ext_sW(
		handle.get(),
		(PWSTR)dn.data(),
		LDAP_SCOPE_BASE,
		(PWSTR)filter.data(),
		(PZPWSTR)schemaAttrs.data(),
		FALSE,

		ServerControls,
		nullptr,
		nullptr,
		1000000,

		std::out_ptr(search_message)
	);

	if(search_message)
	{
		auto search_entry = ldap_first_entry(handle.get(), search_message.get());
		func(handle, search_entry);
	}
	#pragma endregion
}
//****************************************************************************************************
void ldap_search_tree(
	std::shared_ptr<LDAP> handle,
	std::wstring dn,
	std::vector<std::wstring> attributes,
	std::function<void(std::shared_ptr<LDAP>, LDAPMessage*)> func,
	std::wstring_view filter = L"objectClass=*"
)
{
	#pragma region Initial variables
	LDAP_TIMEVAL tm{ .tv_sec = 1000, .tv_usec = 1000 };
	unsigned long pageSize = 100;
	unsigned long pageTimeLimit = 100000;
	unsigned long entryCount;
	unsigned long errorCode = LDAP_SUCCESS;
	#pragma endregion

	#pragma region Create correct values for LDAP search
	std::vector<wchar_t*> schemaAttrs;
	std::for_each(attributes.begin(), attributes.end(), [&schemaAttrs](std::wstring& value){ schemaAttrs.push_back(value.data()); });
	schemaAttrs.push_back(nullptr);
	#pragma endregion

	#pragma region Perform main search
	std::unique_ptr<LDAPSearch, decltype(_ldap_search_abandon_page(handle.get()))> page_handle{
		ldap_search_init_pageW(
			handle.get(),
			dn.data(),
			LDAP_SCOPE_SUBTREE,
			(PWSTR)filter.data(),
			(PZPWSTR)schemaAttrs.data(),
			0,
			nullptr,
			nullptr,
			pageTimeLimit,
			pageSize,
			nullptr
		)
	};

	do
	{
		std::unique_ptr<LDAPMessage, _ldap_msgfree> search_message;

		errorCode = ldap_get_next_page_s(
			handle.get(),
			page_handle.get(),
			&tm,
			pageSize,
			&entryCount,
			std::out_ptr(search_message)
		);
		if(search_message)
		{
			auto search_entry = ldap_first_entry(handle.get(), search_message.get());
			while(nullptr != search_entry)
			{
				func(handle, search_entry);
				search_entry = ldap_next_entry(handle.get(), search_entry);
			}
		}
	} while(errorCode == LDAP_SUCCESS);
	#pragma endregion
}
//****************************************************************************************************
void ldap_search_element(
	std::shared_ptr<LDAP> handle,
	std::wstring dn,
	std::vector<std::wstring> attributes,
	std::function<void(std::shared_ptr<LDAP>, LDAPMessage*)> func,
	std::wstring_view filter = L"objectClass=*"
)
{
	#pragma region Initial variables
	unsigned long errorCode = LDAP_SUCCESS;
	#pragma endregion

	#pragma region Create correct values for LDAP search
	std::vector<wchar_t*> schemaAttrs;
	std::for_each(attributes.begin(), attributes.end(), [&schemaAttrs](std::wstring& value){ schemaAttrs.push_back(value.data()); });
	schemaAttrs.push_back(nullptr);
	#pragma endregion

	#pragma region Perform LDAP search
	std::unique_ptr<LDAPMessage, _ldap_msgfree> search_message;

	errorCode = ldap_search_sW(
		handle.get(),
		(PWSTR)dn.data(),
		LDAP_SCOPE_BASE,
		(PWSTR)filter.data(),
		(PZPWSTR)schemaAttrs.data(),
		FALSE,
		std::out_ptr(search_message)
	);
	if(search_message)
	{
		auto search_entry = ldap_first_entry(handle.get(), search_message.get());
		func(handle, search_entry);
	}
	#pragma endregion
}
//****************************************************************************************************
std::vector<unsigned char> from_hex_codes(std::string value)
{
	std::vector<unsigned char> result;

	std::stringstream stream(value);
	stream >> std::hex;

	std::copy(std::istream_iterator<int>(stream), std::istream_iterator<int>(), std::back_inserter(result));

	return result;
}
//****************************************************************************************************
std::vector<byte> string_to_guid(std::string value)
{
	#pragma region Initial variables
	std::stringstream stream;

	std::regex regex("([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{12})");
	std::match_results<std::string::const_iterator> match;
	#pragma endregion

	#pragma region Check input string format
	if(false == std::regex_match(value, match, regex))
		throw std::exception("Invalid format of the input string");
	#pragma endregion

	#pragma region Parse input string
	for(size_t i = 1; i < 6; i++)
	{
		size_t index = 0;

		std::string value = match[i];
		std::vector<std::string> chunks(value.size() >> 1, std::string{ 2, ' ' });

		for(auto j = value.begin(); j != value.end(); j += 2)
			std::copy_n(j, 2, chunks[index++].begin());

		if(i < 4)
			std::reverse(chunks.begin(), chunks.end());

		std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::string, char>(stream, " "));
	}
	#pragma endregion

	#pragma region Convert string to binary format
	return from_hex_codes(stream.str());
	#pragma endregion
}
//****************************************************************************************************
std::wstring hex_codes(std::vector<byte> value)
{
	std::wstringstream stream;
	stream << std::setfill(L'0') << std::hex;
	std::for_each(value.begin(), value.end(), [&stream](byte element){ stream << std::setw(2) << (int)element; });

	return stream.str();
}
//****************************************************************************************************
std::wstring guid_to_string(std::vector<byte> value)
{
	#pragma region Initial variables
	std::wstring hex = hex_codes(value);

	std::wstringstream stream;

	std::wregex regex(L"([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{12})");
	std::match_results<std::wstring::const_iterator> match;
	#pragma endregion

	#pragma region Check input string format
	if(false == std::regex_match(hex, match, regex))
		throw std::exception("GUID: invalid Value");
	#pragma endregion

	#pragma region Parse input string
	for(size_t i = 1; i < 6; i++)
	{
		size_t index = 0;

		std::wstring value = match[i];
		std::vector<std::wstring> chunks(value.size() >> 1, std::wstring{ 2, L' ' });

		for(auto j = value.begin(); j != value.end(); j += 2)
			std::copy_n(j, 2, chunks[index++].begin());

		if(i < 4)
			std::reverse(chunks.begin(), chunks.end());

		if((size_t)stream.tellp())
			stream << L"-";

		std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::wstring, wchar_t>(stream));
	}
	#pragma endregion

	return stream.str();
}
//****************************************************************************************************
struct class_info
{
	std::wstring className;
	std::wstring classDName;
	std::vector<byte> classGUID;
	std::vector<std::wstring> classAttributes;
};
//****************************************************************************************************
void check()
{
	std::wstring target_dn = L"CN=Administrator,CN=Users,DC=WDOMAIN,DC=LAN";

	#pragma region Aux "using" declarations
	using valuesPtr = std::unique_ptr<berval* [], _ldap_value_free_len>;
	#pragma endregion

	#pragma region Initial variables
	std::vector<byte> majorClassGUID;
	std::vector<byte> majorClassSecurityDescriptor;

	std::vector<std::wstring> classes;
	std::wstring majorClassName;
	std::wstring majorClassDName;

	std::vector<class_info> classInfos;

	std::map<std::wstring, std::vector<byte>> attributes;
	std::map<std::vector<byte>, std::vector<std::vector<byte>>> propertySets;
	std::vector<std::vector<byte>> freeProperties;
	std::map<std::vector<byte>, int> extendedRights;

	std::vector<std::wstring> childClassesNames;
	std::vector<std::vector<byte>> childClassesGUIDs;
	#pragma endregion

	#pragma region Initialize connection to LDAP server
	auto handle = ldap_init_connection();
	#pragma endregion

	#pragma region Find all namespace contexts
	auto contexts = ldap_search_contexts(handle);
	#pragma endregion

	#pragma region Find major class for particular object instance
	auto classFind = [&classes, contexts, &majorClassSecurityDescriptor](std::shared_ptr<LDAP> handle, LDAPMessage* entry)
	{
		#pragma region Initial variables
		ULONG i = 0;
		#pragma endregion

		valuesPtr objectClassValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"objectClass") };
		if(!objectClassValues)
			throw std::exception("Cannot get objectClass values from DN");

		#pragma region Major class name would be very least in the array
		while(objectClassValues[i] != nullptr)
			classes.emplace_back(string_to_wstring(objectClassValues[i++]->bv_val));

		if(!classes.size())
			throw std::exception("Cannot find major class name");
		#pragma endregion

		#pragma region Find object class name
		valuesPtr nTSecurityDescriptorValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"nTSecurityDescriptor") };
		if(!nTSecurityDescriptorValues)
			throw std::exception("Cannot get nTSecurityDescriptor for target DN");

		majorClassSecurityDescriptor.insert(
			majorClassSecurityDescriptor.end(),
			nTSecurityDescriptorValues[0]->bv_val,
			nTSecurityDescriptorValues[0]->bv_val + nTSecurityDescriptorValues[0]->bv_len
		);
		#pragma endregion
	};

	ldap_search_element_ext(
		handle,
		target_dn,
		{ L"objectClass", L"nTSecurityDescriptor" },
		classFind
	);

	majorClassName = classes[classes.size() - 1];
	#pragma endregion

	#pragma region Find other necessary information for all classes
	auto classInfosFind = [&majorClassGUID, &classes, &classInfos, majorClassName, &majorClassDName](std::shared_ptr<LDAP> handle, LDAPMessage* entry)
	{
		#pragma region Find object class name
		valuesPtr nameValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"lDAPDisplayName") };
		if(!nameValues)
			throw std::exception("Cannot get values for lDAPDisplayName");
		#pragma endregion

		#pragma region Find object class distinguished name
		valuesPtr dNameValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"distinguishedName") };
		if(!dNameValues)
			throw std::exception("Cannot get values for distinguishedName");
		#pragma endregion

		#pragma region Find object GUID
		valuesPtr guidValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"schemaIDGUID") };
		if(!guidValues)
			throw std::exception("Cannot get values for schemaIDGUID");

		std::vector<byte> guid{ guidValues[0]->bv_val, guidValues[0]->bv_val + guidValues[0]->bv_len };
		#pragma endregion

		#pragma region Append all possible attributes of the class
		std::vector<std::wstring> attributes;

		valuesPtr mayContainValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"mayContain") };
		if(mayContainValues)
		{
			ULONG i = 0;
			while(mayContainValues[i] != nullptr)
				attributes.emplace_back(string_to_wstring(mayContainValues[i++]->bv_val));
		}

		valuesPtr mustContainValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"mustContain") };
		if(mustContainValues)
		{
			ULONG i = 0;
			while(mustContainValues[i] != nullptr)
				attributes.emplace_back(string_to_wstring(mustContainValues[i++]->bv_val));
		}

		valuesPtr systemMayContainValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"systemMayContain") };
		if(systemMayContainValues)
		{
			ULONG i = 0;
			while(systemMayContainValues[i] != nullptr)
				attributes.emplace_back(string_to_wstring(systemMayContainValues[i++]->bv_val));
		}

		valuesPtr systemMustContainValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"systemMustContain") };
		if(systemMustContainValues)
		{
			ULONG i = 0;
			while(systemMustContainValues[i] != nullptr)
				attributes.emplace_back(string_to_wstring(systemMustContainValues[i++]->bv_val));
		}
		#pragma endregion

		#pragma region Append all aux classes to global class array
		valuesPtr auxClassValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"auxiliaryClass") };
		if(auxClassValues)
		{
			ULONG i = 0;
			while(auxClassValues[i] != nullptr)
				classes.emplace_back(string_to_wstring(auxClassValues[i++]->bv_val));
		}

		valuesPtr sysAuxClassValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"systemAuxiliaryClass") };
		if(sysAuxClassValues)
		{
			ULONG i = 0;
			while(sysAuxClassValues[i] != nullptr)
				classes.emplace_back(string_to_wstring(sysAuxClassValues[i++]->bv_val));
		}
		#pragma endregion

		auto className = string_to_wstring(nameValues[0]->bv_val);
		auto classDName = string_to_wstring(dNameValues[0]->bv_val);

		if(className == majorClassName)
		{
			majorClassDName = classDName;
			majorClassGUID = guid;
		}

		classInfos.push_back({
			.className = className,
			.classDName = classDName,
			.classGUID = guid,
			.classAttributes = attributes
			});
	};

	// Because inside lambda we updating primary array 
	// it is neccessary to use position indexes only
	size_t pos = 0;

	while(pos != classes.size())
	{
		ldap_search_tree(
			handle,
			contexts[L"schema"],
			{
				L"lDAPDisplayName",
				L"distinguishedName",
				L"schemaIDGUID",
				L"mayContain",
				L"mustContain",
				L"systemMayContain",
				L"systemMustContain",
				L"auxiliaryClass",
				L"systemAuxiliaryClass"
			},
			classInfosFind,
			std::format(L"lDAPDisplayName={}", classes[pos])
		);

		pos++;
	}
	#pragma endregion

	#pragma region Find child object classes
	auto childFind = [&childClassesNames](std::shared_ptr<LDAP> handle, LDAPMessage* entry)
	{
		valuesPtr possibleInferiorsValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"possibleInferiors") };
		if(possibleInferiorsValues)
		{
			ULONG i = 0;
			while(possibleInferiorsValues[i] != nullptr)
				childClassesNames.emplace_back(string_to_wstring(possibleInferiorsValues[i++]->bv_val));
		}
	};

	ldap_search_element(
		handle,
		majorClassDName,
		{ L"possibleInferiors" },
		childFind
	);

	auto childGUIDFind = [&childClassesGUIDs](std::shared_ptr<LDAP> handle, LDAPMessage* entry)
	{
		valuesPtr schemaIDGUIDValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"schemaIDGUID") };
		if(!schemaIDGUIDValues)
			throw std::exception("Cannot find schemaIDGUIDValues");

		childClassesGUIDs.push_back({ schemaIDGUIDValues[0]->bv_val, schemaIDGUIDValues[0]->bv_val + schemaIDGUIDValues[0]->bv_len });
	};

	for(auto&& element : childClassesNames)
	{
		ldap_search_tree(
			handle,
			contexts[L"schema"],
			{
				L"lDAPDisplayName",
				L"schemaIDGUID"
			},
			childGUIDFind,
			std::format(L"lDAPDisplayName={}", element)
		);
	}
	#pragma endregion

	#pragma region Find information about all attributes
	for(auto&& element : classInfos)
	{
		for(auto&& attribute : element.classAttributes)
		{
			std::transform(attribute.begin(), attribute.end(), attribute.begin(), tolower);
			attributes[attribute] = {};
		}
	}

	auto attributesFind = [&attributes, &propertySets, &freeProperties](std::shared_ptr<LDAP> handle, LDAPMessage* entry)
	{
		#pragma region Find name of the attribute
		valuesPtr nameValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"lDAPDisplayName") };
		if(!nameValues)
			throw std::exception("Cannot get values for lDAPDisplayName");

		std::wstring name = string_to_wstring(nameValues[0]->bv_val);
		std::transform(name.begin(), name.end(), name.begin(), tolower);
		#pragma endregion

		#pragma region Find object GUID
		valuesPtr guidValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"schemaIDGUID") };
		if(!guidValues)
			throw std::exception("Cannot get values for schemaIDGUID");

		std::vector<byte> guid{ guidValues[0]->bv_val, guidValues[0]->bv_val + guidValues[0]->bv_len };
		#pragma endregion

		#pragma region Find information about property set which includes the attribute
		valuesPtr attributeSecurityGUID{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"attributeSecurityGUID") };
		if(attributeSecurityGUID)
		{
			std::vector<byte> secguid{ attributeSecurityGUID[0]->bv_val, attributeSecurityGUID[0]->bv_val + attributeSecurityGUID[0]->bv_len };

			if(propertySets.contains(secguid))
				propertySets[secguid].push_back(guid);
			else
				propertySets[secguid] = { guid };
		}
		else
			freeProperties.push_back(guid);
		#pragma endregion

		attributes[name] = guid;
	};

	for(auto&& [key, value] : attributes)
	{
		ldap_search_tree(
			handle,
			contexts[L"schema"],
			{
				L"lDAPDisplayName",
				L"attributeSecurityGUID",
				L"schemaIDGUID"
			},
			attributesFind,
			std::format(L"lDAPDisplayName={}", key)
		);
	}
	#pragma endregion

	#pragma region Find information about all applicable extended rights
	auto rightsFind = [&propertySets, &extendedRights](std::shared_ptr<LDAP> handle, LDAPMessage* entry)
	{
		#pragma region Find object GUID
		valuesPtr guidValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"rightsGuid") };
		if(!guidValues)
			throw std::exception("Cannot get values for rightsGuid");

		std::string guid_str = guidValues[0]->bv_val;
		std::transform(guid_str.begin(), guid_str.end(), guid_str.begin(), tolower);

		std::vector<byte> guid = string_to_guid(guid_str);
		#pragma endregion

		#pragma region Get validAccesses value
		valuesPtr validAccessesValues{ ldap_get_values_lenW(handle.get(), entry, (PWSTR)L"validAccesses") };
		if(!validAccessesValues)
			throw std::exception("Cannot get values for validAccesses");

		auto validAccesses = std::stoi(validAccessesValues[0]->bv_val);
		#pragma endregion

		#pragma region Check what type of entry do we have
		if(validAccesses & (0x00000010 | 0x00000020)) // Should be property set
		{
			// Could be that property set has no entries
			if(!propertySets.contains(guid))
				propertySets[guid] = {};
		}
		else // Other types: control rights or validated writes
			extendedRights[guid] = 1;
		#pragma endregion
	};

	for(auto&& element : classInfos)
	{
		ldap_search_tree(
			handle,
			contexts[L"config"],
			{
				L"rightsGuid",
				L"validAccesses"
			},
			rightsFind,
			std::format(L"(&(objectClass=controlAccessRight)(appliesTo={}))", guid_to_string(element.classGUID))
		);
	}
	#pragma endregion

	#pragma region Build final object type list
	std::vector<OBJECT_TYPE_LIST> object_list;

	#pragma region Major class GUID is on top of the list
	object_list.push_back({ ACCESS_OBJECT_GUID, 0, (GUID*)majorClassGUID.data() });
	#pragma endregion

	#pragma region Add all extended rights first
	for(auto&& element : extendedRights)
		object_list.push_back({ ACCESS_PROPERTY_SET_GUID, 0, (GUID*)element.first.data() });
	#pragma endregion

	#pragma region Add all property sets
	for(auto&& element : propertySets)
	{
		object_list.push_back({ ACCESS_PROPERTY_SET_GUID, 0, (GUID*)element.first.data() });

		for(auto&& prop : element.second)
			object_list.push_back({ ACCESS_PROPERTY_GUID, 0, (GUID*)prop.data() });
	}
	#pragma endregion

	#pragma region Add all properties which are not in any property set
	for(auto&& element : freeProperties)
		object_list.push_back({ ACCESS_PROPERTY_SET_GUID, 0, (GUID*)element.data() });
	#pragma endregion

	#pragma region Add all child classes
	for(auto&& element : childClassesGUIDs)
		object_list.push_back({ ACCESS_PROPERTY_SET_GUID, 0, (GUID*)element.data() });
	#pragma endregion
	#pragma endregion

	#pragma region Perform access checking
	HANDLE token;

	if(!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &token))
		throw std::exception("Cannot get process token");

	HANDLE dup_token;
	if(FALSE == DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityDelegation, TokenImpersonation, &dup_token))
		throw std::exception("Cannot duplicate token");

	size_t size = object_list.size();

	std::vector<DWORD> granted_access(size, 0);
	std::vector<DWORD> access_status(size, 0);

	std::vector<DWORD> sacl_eval_results(size, 0);
	std::vector<DWORD> errors(size, 0);

	PSID sid_self = NULL;
	AUTHZ_RESOURCE_MANAGER_HANDLE   AuthzResMgrHandle = NULL;
	AUTHZ_CLIENT_CONTEXT_HANDLE     AuthzClientHandle = NULL;
	LUID                            ZeroLuid = { 0, 0 };
	AUTHZ_ACCESS_REQUEST            AccessRequest = {
		MAXIMUM_ALLOWED,
		sid_self,
		object_list.data(),
		(DWORD)object_list.size(),
		NULL
	};
	AUTHZ_ACCESS_REPLY AccessReply = { 0 };
	AccessReply.ResultListLength = (DWORD)object_list.size();
	AccessReply.GrantedAccessMask = granted_access.data();
	AccessReply.SaclEvaluationResults = sacl_eval_results.data();
	AccessReply.Error = errors.data();

	if(!AuthzInitializeResourceManager(
		AUTHZ_RM_FLAG_NO_AUDIT,
		NULL,
		NULL,
		NULL,
		NULL,
		&AuthzResMgrHandle
	))
	{
		throw std::exception("AuthzInitializeResourceManager: error");
	}

	if(!AuthzInitializeContextFromToken(
		0,
		dup_token,
		AuthzResMgrHandle,
		NULL,
		ZeroLuid,
		NULL,
		&AuthzClientHandle
	))
	{
		throw std::exception("AuthzInitializeContextFromToken: error");
	}

	auto check_result = AuthzAccessCheck(
		0,
		AuthzClientHandle,
		&AccessRequest,
		NULL,
		(PSECURITY_DESCRIPTOR)majorClassSecurityDescriptor.data(),
		NULL,
		0,
		&AccessReply,
		NULL
	);
	if(FALSE == check_result)
	{
		std::stringstream stream;
		stream << "AccessCheck: error during a check, #" << GetLastError() << "\n";

		throw std::exception(stream.str().c_str());
	}
	#pragma endregion
}
//****************************************************************************************************
int main()
{
	check();
	return 0;
}
//****************************************************************************************************
