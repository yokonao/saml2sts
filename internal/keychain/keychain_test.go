package keychain

import (
	"fmt"
	"os"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	item := Item{Service: fmt.Sprintf("saml2sts.test.%d", os.Getpid()), Account: "test"}
	t.Cleanup(func() { _ = Delete(item) })

	if data, err := Read(item); data != nil || err != nil {
		t.Fatalf("Read of a missing item = %q, %v", data, err)
	}
	for _, v := range []string{"first", "second"} {
		if err := Write(item, []byte(v)); err != nil {
			t.Fatal(err)
		}
		if data, err := Read(item); string(data) != v || err != nil {
			t.Fatalf("Read = %q, %v; want %q", data, err, v)
		}
	}
	if err := Delete(item); err != nil {
		t.Fatal(err)
	}
	if err := Delete(item); err != nil {
		t.Fatalf("Delete of a missing item: %v", err)
	}
}

func TestDeleteService(t *testing.T) {
	service := fmt.Sprintf("saml2sts.test.%d.all", os.Getpid())
	items := []Item{{Service: service, Account: "a"}, {Service: service, Account: "b"}}
	t.Cleanup(func() { _ = DeleteService(service) })
	for _, it := range items {
		if err := Write(it, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeleteService(service); err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if data, err := Read(it); data != nil || err != nil {
			t.Errorf("%s still there: %q, %v", it.Account, data, err)
		}
	}
	if err := DeleteService(service); err != nil {
		t.Errorf("DeleteService of nothing: %v", err)
	}
}
