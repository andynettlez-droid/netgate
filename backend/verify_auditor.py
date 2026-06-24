from auditor import ConfigAuditor

def test_auditor():
    test_config = """hostname Test-Router
no service password-encryption
enable password cleartextpassword123
!
interface GigabitEthernet0/1
 shutdown
!
interface GigabitEthernet0/2
!
snmp-server community public RO
!
line vty 0 4
 transport input telnet
!"""

    print("=== Testing ConfigAuditor against mock insecure config ===")
    auditor = ConfigAuditor(test_config)
    results = auditor.run_all_checks()

    all_failed = True
    for result in results:
        print(f"[{result['status']}] {result['id']} - {result['title']} (Severity: {result['severity']})")
        print(f"  Details: {result['details']}\n")
        
        # Verify that all rules fail as expected on this insecure config
        if result['status'] == "PASSED":
            all_failed = False

    if all_failed:
        print(">>> SUCCESS: ConfigAuditor successfully flagged all insecure configurations!")
    else:
        print(">>> FAILURE: ConfigAuditor missed some security warnings.")

if __name__ == "__main__":
    test_auditor()
