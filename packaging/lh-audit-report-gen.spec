Name:           lh-audit-report-gen
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-report-gen - Native PDF-1.4 Cross-Reference Binary Offset Invariant
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-audit-report-gen
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Zero-dependency TypeScript ISO/IEC 27001:2022 Annex A & CERT-In compliance audit report generator featuring a native %PDF-1.4 binary compiler, multi-SARIF v2.1.0 deduplicator, and cryptographic evidence sealing.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-report-gen ]; then
    install -m 0755 bin/lh-report-gen %{buildroot}%{_bindir}/lh-report-gen
elif [ -f lh-report-gen ]; then
    install -m 0755 lh-report-gen %{buildroot}%{_bindir}/lh-report-gen
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-audit-report-gen.
