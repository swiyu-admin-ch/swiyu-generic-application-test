package ch.admin.bj.swiyu.swiyu_test_wallet.issuer;

import ch.admin.bj.swiyu.gen.issuer.model.CredentialOfferMetadataDto;
import lombok.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@NoArgsConstructor
@Getter
@Setter
public class CredentialOffer {
    private Map<String, Object> credentialSubjectData = new HashMap<>();
    private Map<String, Object> credentialMetadata = new HashMap<>();
    private List<String> statusLists = new ArrayList<>();
    private List<String> metadataCredentialSupported;
    private Integer offerValiditySeconds;
    private String credentialValidFrom;
    private String credentialValidUntil;

    public CredentialOffer addStatusList(String statusList){
        if (statusLists == null)
            statusLists = new ArrayList<>();
        this.statusLists.add(statusList);
        return this;
    }

    public CredentialOffer putCredentialSubjectData(String key, Object value){
        this.credentialSubjectData.put(key, value);
        return this;
    }

    public static Map<String, Object> defaultSubjectData() {

        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("type", "Bachelor of Science");
        subjectData.put("name", "Data Science");
        subjectData.put("average_grade", "5.33");

        return subjectData;
    }

    public static CredentialOfferMetadataDto defaultMetadata() {
        CredentialOfferMetadataDto metadata = new CredentialOfferMetadataDto();
        metadata.setDeferred(false);
        metadata.setVctHashIntegrity("sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=");

        return metadata;
    }

    public List<String> getSortedCredentialKeys() {
        List<String> offeredCredentialKeys = new ArrayList<>(credentialSubjectData.keySet());
        Collections.sort(offeredCredentialKeys);
        return offeredCredentialKeys;
    }

    public CredentialOffer setAsDeferred() {
        getCredentialMetadata().put("deferred", Boolean.TRUE);
        return this;
    }
}
