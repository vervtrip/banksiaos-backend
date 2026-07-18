
# Banksia OS — Database Integrity Audit
**Generated:** 2026-07-15T20:34:43.441888
**Database:** /root/banksia-dashboard/banksia_os.db

## 1. Table Overview
| Table | Records | PK Columns | Has created | Has modified | FK Count | Index Count |
| --- | --- | --- | --- | --- | --- | --- |
| access_records | 11 | id | ❌ | ❌ | 2 | 2 |
| activity_log | 72 | id | ✅ | ❌ | 0 | 2 |
| applicants | 682 | id | ✅ | ✅ | 2 | 2 |
| comments | 5 | id | ✅ | ❌ | 0 | 1 |
| company_settings | 9 | id | ❌ | ❌ | 0 | 1 |
| conversation_timeline | 0 | id | ❌ | ❌ | 0 | 3 |
| deposits | 148 | id | ✅ | ✅ | 4 | 6 |
| documents | 1 | id | ✅ | ❌ | 0 | 0 |
| esignature_audit_log | 7 | id | ❌ | ❌ | 1 | 2 |
| esignature_requests | 1 | id | ✅ | ❌ | 2 | 4 |
| form_sections | 195 | id | ❌ | ❌ | 1 | 2 |
| guarantors | 4 | id | ✅ | ✅ | 1 | 0 |
| invoices | 2 | id | ✅ | ❌ | 2 | 0 |
| ll_communications | 0 | id | ✅ | ❌ | 1 | 0 |
| maintenance_jobs | 200 | id | ✅ | ✅ | 2 | 1 |
| maintenance_orders | 1 | id | ✅ | ✅ | 1 | 0 |
| maintenance_requests | 2 | id | ✅ | ✅ | 0 | 1 |
| message_threads | 2 | id | ✅ | ✅ | 0 | 0 |
| messages | 6 | id | ✅ | ❌ | 1 | 0 |
| migration_log | 1 | id | ❌ | ❌ | 0 | 1 |
| notifications | 25 | id | ✅ | ❌ | 0 | 1 |
| portal_sessions | 9 | id | ✅ | ❌ | 1 | 3 |
| portal_users | 2 | id | ✅ | ✅ | 2 | 3 |
| properties | 67 | id | ✅ | ✅ | 0 | 2 |
| property_images | 0 | id | ❌ | ❌ | 2 | 2 |
| property_owners | 2 | id | ✅ | ✅ | 0 | 0 |
| referencing_checks | 18 | id | ✅ | ❌ | 1 | 3 |
| referencing_documents | 0 | id | ❌ | ❌ | 1 | 3 |
| referencing_forms | 10 | id | ✅ | ✅ | 1 | 4 |
| referencing_forms_backup | 0 | NONE | ✅ | ✅ | 0 | 0 |
| rent_charges | 2084 | id | ✅ | ✅ | 0 | 2 |
| sqlite_sequence | 33 | NONE | ❌ | ❌ | 0 | 0 |
| sync_conflicts | 20 | id | ❌ | ❌ | 0 | 0 |
| tags | 13 | id | ❌ | ❌ | 0 | 1 |
| tenancies | 470 | id | ✅ | ✅ | 1 | 3 |
| tenants | 535 | id | ✅ | ✅ | 1 | 3 |
| transactions | 7293 | id | ✅ | ✅ | 0 | 5 |
| units | 193 | id | ✅ | ✅ | 1 | 3 |

# 2. Orphan Records (FK references to non-existent parents)

### Tenants with tenancy_id that doesn't exist in tenancies
- **Count:** 0
```
SELECT t.id, t.first_name, t.last_name, t.tenancy_id
      FROM tenants t LEFT JOIN tenancies tn ON t.tenancy_id = tn.id
      WHERE t.tenancy_id IS NOT NULL AND tn.id IS NULL
```
---

### Tenants with property_id that doesn't exist in properties
- **Count:** 530
```
SELECT t.id, t.first_name, t.last_name, t.property_id
      FROM tenants t LEFT JOIN properties p ON t.property_id = p.id
      WHERE t.property_id IS NOT NULL AND p.id IS NULL
```
- **Sample records (up to 10):**
  - {'id': 2617, 'first_name': 'Safoora', 'last_name': 'Kumbalakkuzhi', 'property_id': 331625}
  - {'id': 2618, 'first_name': 'Jeni', 'last_name': 'Mathew', 'property_id': 328079}
  - {'id': 2619, 'first_name': 'Daniel', 'last_name': 'Ferrier', 'property_id': 330203}
  - {'id': 2620, 'first_name': 'GURPREET', 'last_name': 'KAUR', 'property_id': 317213}
  - {'id': 2621, 'first_name': 'Jayden', 'last_name': 'Newman', 'property_id': 324471}
  - {'id': 2622, 'first_name': 'Tamara', 'last_name': 'Kubacka', 'property_id': 330203}
  - {'id': 2623, 'first_name': 'KAMURUNNAHAR', 'last_name': 'MONY', 'property_id': 321959}
  - {'id': 2624, 'first_name': 'SM  ASADUZZAMAN', 'last_name': 'KANOK', 'property_id': 321959}
  - {'id': 2625, 'first_name': 'Shah Mohammad Samiul Kabir', 'last_name': 'Chowdhury', 'property_id': 321959}
  - {'id': 2626, 'first_name': 'Méline', 'last_name': 'Desault', 'property_id': 308266}
---

### Tenancies with property_id not in properties
- **Count:** 0
```
SELECT tn.id, tn.ref, tn.property_id
      FROM tenancies tn LEFT JOIN properties p ON tn.property_id = p.id
      WHERE tn.property_id IS NOT NULL AND p.id IS NULL
```
---

### Tenancies with unit_id not in units
- **Count:** 0
```
SELECT tn.id, tn.ref, tn.unit_id
      FROM tenancies tn LEFT JOIN units u ON tn.unit_id = u.id
      WHERE tn.unit_id IS NOT NULL AND u.id IS NULL
```
---

### Units with property_id not in properties
- **Count:** 0
```
SELECT u.id, u.unit_ref, u.property_id
      FROM units u LEFT JOIN properties p ON u.property_id = p.id
      WHERE u.property_id IS NOT NULL AND p.id IS NULL
```
---

### Deposits with tenancy_id not in tenancies
- **Count:** 0
```
SELECT d.id, d.tenancy_id FROM deposits d
      LEFT JOIN tenancies tn ON d.tenancy_id = tn.id
      WHERE d.tenancy_id IS NOT NULL AND tn.id IS NULL
```
---

### Deposits with tenant_id not in tenants
- **Count:** 0
```
SELECT d.id, d.tenant_id FROM deposits d
      LEFT JOIN tenants t ON d.tenant_id = t.id
      WHERE d.tenant_id IS NOT NULL AND t.id IS NULL
```
---

### Maintenance jobs with property_id not in properties
- **Count:** 0
```
SELECT mj.id, mj.reference, mj.property_id FROM maintenance_jobs mj
      LEFT JOIN properties p ON mj.property_id = p.id
      WHERE mj.property_id IS NOT NULL AND p.id IS NULL
```
---

### Documents with property_id not in properties
- **Count:** 0
```
SELECT d.id, d.filename, d.related_id FROM documents d
      WHERE d.related_to = 'property' AND d.related_id IS NOT NULL
      AND d.related_id NOT IN (SELECT id FROM properties)
```
---

### Documents with tenancy_id not in tenancies
- **Count:** 0
```
SELECT d.id, d.filename, d.related_id FROM documents d
      WHERE d.related_to = 'tenancy' AND d.related_id IS NOT NULL
      AND d.related_id NOT IN (SELECT id FROM tenancies)
```
---

### Documents with tenant_id not in tenants
- **Count:** 0
```
SELECT d.id, d.filename, d.related_id FROM documents d
      WHERE d.related_to = 'tenant' AND d.related_id IS NOT NULL
      AND d.related_id NOT IN (SELECT id FROM tenants)
```
---

### Applicants with property_id not in properties
- **Count:** 0
```
SELECT a.id, a.first_name, a.last_name, a.property_id FROM applicants a
      LEFT JOIN properties p ON a.property_id = p.id
      WHERE a.property_id IS NOT NULL AND p.id IS NULL
```
---

### Applicants with unit_id not in units
- **Count:** 0
```
SELECT a.id, a.first_name, a.last_name, a.unit_id FROM applicants a
      LEFT JOIN units u ON a.unit_id = u.id
      WHERE a.unit_id IS NOT NULL AND u.id IS NULL
```
---

### Referencing forms with applicant_id not in applicants
- **Count:** 0
```
SELECT rf.id, rf.first_name, rf.last_name, rf.applicant_id FROM referencing_forms rf
      LEFT JOIN applicants a ON rf.applicant_id = a.id
      WHERE rf.applicant_id IS NOT NULL AND a.id IS NULL
```
---

### Invoices with tenancy_id not in tenancies
- **Count:** 0
```
SELECT i.id, i.invoice_ref, i.tenancy_id FROM invoices i
      LEFT JOIN tenancies tn ON i.tenancy_id = tn.id
      WHERE i.tenancy_id IS NOT NULL AND tn.id IS NULL
```
---

### Guarantors with applicant_id not in applicants
- **Count:** 0
```
SELECT g.id, g.first_name, g.last_name, g.applicant_id FROM guarantors g
      LEFT JOIN applicants a ON g.applicant_id = a.id
      WHERE g.applicant_id IS NOT NULL AND a.id IS NULL
```
---

### Maintenance requests with property_id not in properties
- **Count:** 0
```
SELECT mr.id, mr.reference, mr.property_id FROM maintenance_requests mr
      LEFT JOIN properties p ON mr.property_id = p.id
      WHERE mr.property_id IS NOT NULL AND p.id IS NULL
```
---

### Maintenance requests with tenancy_id not in tenancies
- **Count:** 0
```
SELECT mr.id, mr.reference, mr.tenancy_id FROM maintenance_requests mr
      LEFT JOIN tenancies tn ON mr.tenancy_id = tn.id
      WHERE mr.tenancy_id IS NOT NULL AND tn.id IS NULL
```
---

### Maintenance jobs with tenant_id not in tenants
- **Count:** 0
```
SELECT mj.id, mj.reference, mj.tenant_id FROM maintenance_jobs mj
      LEFT JOIN tenants t ON mj.tenant_id = t.id
      WHERE mj.tenant_id IS NOT NULL AND t.id IS NULL
```
---

# 3. Duplicate Records

### Duplicate unit_ref within same property_id
- **Count:** 2
```
SELECT u.property_id, u.unit_ref, COUNT(*) AS cnt, GROUP_CONCAT(u.id) AS ids
      FROM units u WHERE u.unit_ref IS NOT NULL AND u.unit_ref != ''
      GROUP BY u.property_id, u.unit_ref HAVING COUNT(*) > 1
```
- **Sample duplicates (up to 10):**
  - {'property_id': 100001, 'unit_ref': 'Room B', 'cnt': 2, 'ids': '990,992'}
  - {'property_id': 100001, 'unit_ref': 'Room C', 'cnt': 2, 'ids': '991,993'}
---

### Duplicate property_ref
- **Count:** 0
```
SELECT p.property_ref, COUNT(*) AS cnt, GROUP_CONCAT(p.id) AS ids
      FROM properties p WHERE p.property_ref IS NOT NULL AND p.property_ref != ''
      GROUP BY p.property_ref HAVING COUNT(*) > 1
```
---

### Duplicate email within tenants
- **Count:** 27
```
SELECT t.email, COUNT(*) AS cnt, GROUP_CONCAT(t.id) AS ids,
             GROUP_CONCAT(t.first_name || ' ' || t.last_name) AS names
      FROM tenants t WHERE t.email IS NOT NULL AND t.email != ''
      GROUP BY t.email HAVING COUNT(*) > 1
```
- **Sample duplicates (up to 10):**
  - {'email': 'WeAreDeliverX@gmail.com', 'cnt': 2, 'ids': '2718,2840', 'names': 'Scott Moulds,Scott Moulds'}
  - {'email': 'bilibok.istvan@gmail.hu', 'cnt': 2, 'ids': '2715,3093', 'names': 'Istvan Bilibok,Istvan Bilibok'}
  - {'email': 'chaudhary27shivani@gmail.com', 'cnt': 2, 'ids': '3014,3137', 'names': 'Shivani Chaudhary,Shivani Chaudhary'}
  - {'email': 'cjswndms3620@naver.com', 'cnt': 2, 'ids': '2825,2826', 'names': 'Jooeun Chun,Jooeun Chun'}
  - {'email': 'conno0409@gmail.com', 'cnt': 2, 'ids': '2998,3072', 'names': 'Conno Liu,Conno Liu'}
  - {'email': 'cyroannes@icloud.com', 'cnt': 2, 'ids': '2642,2827', 'names': 'Cyro Faria Annes,Cyro Faria Annes'}
  - {'email': 'dipsita1das@gmail.com', 'cnt': 2, 'ids': '2991,3102', 'names': 'Dipsita Das,Dipsita Das'}
  - {'email': 'graeme.robert13@gmail.com', 'cnt': 2, 'ids': '2804,2854', 'names': 'Graeme Holliday,Graeme Holliday'}
  - {'email': 'gullyregan@gmail.com', 'cnt': 2, 'ids': '2918,2923', 'names': 'Regan Gully,Regan Forbes Gully'}
  - {'email': 'hasimgezegen@hotmail.com', 'cnt': 2, 'ids': '3011,3033', 'names': 'Hasim Gezegen,Hasim Gezegen'}
---

### Duplicate applicant emails
- **Count:** 27
```
SELECT a.email, COUNT(*) AS cnt, GROUP_CONCAT(a.id) AS ids,
             GROUP_CONCAT(a.first_name || ' ' || a.last_name) AS names
      FROM applicants a WHERE a.email IS NOT NULL AND a.email != ''
      GROUP BY a.email HAVING COUNT(*) > 1
```
- **Sample duplicates (up to 10):**
  - {'email': 'WeAreDeliverX@gmail.com', 'cnt': 2, 'ids': '2788,2928', 'names': 'Scott moulds,Scott Moulds'}
  - {'email': 'aiswaryaos991@gmail.com', 'cnt': 2, 'ids': '3014,3022', 'names': 'Aiswarya Othayamangalam sasi,Aiswarya Othayamangalam'}
  - {'email': 'aleks.budnik.16@gmail.com', 'cnt': 2, 'ids': '3041,3045', 'names': 'Aleksandra Budnik,Aleksandra Cecylia Budnik'}
  - {'email': 'ayden@xaanderstevens.com', 'cnt': 2, 'ids': '3199,3203', 'names': 'Ayden Stevens,Ayden Stevens'}
  - {'email': 'bilibok.istvan@gmail.hu', 'cnt': 2, 'ids': '2787,3297', 'names': 'Istvan Bilibok,Istvan Bilibok'}
  - {'email': 'chamathvijay13@gmail.com', 'cnt': 2, 'ids': '3038,3043', 'names': 'Chamathvi Liyana Atukoralage,Liyana Atukoralage Chamathvi Yuhansa'}
  - {'email': 'cyroannes@icloud.com', 'cnt': 2, 'ids': '2716,2918', 'names': 'Cyro Faria Annes,Cyro Faria Annes'}
  - {'email': 'enricovighi90@gmail.com', 'cnt': 2, 'ids': '3019,3021', 'names': 'Enrico Vighi,Enrico Vighi'}
  - {'email': 'gaudentialaura@gmail.com', 'cnt': 2, 'ids': '3148,3150', 'names': 'Gaudentia Laura Gisela,Gaudentia Laura Gisela'}
  - {'email': 'george.rawlinson1@gmail.com', 'cnt': 2, 'ids': '3023,3024', 'names': 'George Rawlinson,George Rawlinson'}
---

# 4. Missing Relationships

### Tenants with no tenancy_id
- **Count:** 0
```
SELECT id, first_name, last_name, property_id FROM tenants
      WHERE tenancy_id IS NULL
```
---

### Tenancies with no unit_id
- **Count:** 0
```
SELECT id, ref, property_id FROM tenancies WHERE unit_id IS NULL
```
---

### Tenancies with no property_id
- **Count:** 0
```
SELECT id, ref, unit_id FROM tenancies WHERE property_id IS NULL
```
---

### Units with no tenancies at all (vacant with no tenancy history)
- **Count:** 32
```
SELECT u.id, u.unit_ref, u.property_id FROM units u
      WHERE u.id NOT IN (SELECT DISTINCT unit_id FROM tenancies WHERE unit_id IS NOT NULL)
```
- **Sample records (up to 10):**
  - {'id': 803, 'unit_ref': 'Room 3', 'property_id': 242}
  - {'id': 835, 'unit_ref': 'Flat 1, 77A Brick Lane, E1 6QL', 'property_id': 248}
  - {'id': 900, 'unit_ref': 'D2', 'property_id': 271}
  - {'id': 961, 'unit_ref': 'Test Room 1', 'property_id': 241}
  - {'id': 962, 'unit_ref': 'Audit Room', 'property_id': 241}
  - {'id': 964, 'unit_ref': 'R2', 'property_id': 100001}
  - {'id': 965, 'unit_ref': 'R1', 'property_id': 100002}
  - {'id': 966, 'unit_ref': 'R2', 'property_id': 100002}
  - {'id': 967, 'unit_ref': 'R1', 'property_id': 100004}
  - {'id': 968, 'unit_ref': 'R2', 'property_id': 100004}
---

### Deposits with no protection reference
- **Count:** 33
```
SELECT d.id, d.amount, d.tenancy_id, d.protection_status FROM deposits d
      WHERE (d.protection_reference IS NULL OR d.protection_reference = '')
      AND d.protection_status != 'unprotected'
```
- **Sample records (up to 10):**
  - {'id': 18, 'amount': 980.0, 'tenancy_id': 2307, 'protection_status': 'protected'}
  - {'id': 20, 'amount': 850.0, 'tenancy_id': 2309, 'protection_status': 'protected'}
  - {'id': 21, 'amount': 800.0, 'tenancy_id': 2310, 'protection_status': 'protected'}
  - {'id': 22, 'amount': 650.0, 'tenancy_id': 2311, 'protection_status': 'protected'}
  - {'id': 24, 'amount': 840.0, 'tenancy_id': 2313, 'protection_status': 'protected'}
  - {'id': 25, 'amount': 700.0, 'tenancy_id': 2314, 'protection_status': 'protected'}
  - {'id': 29, 'amount': 1300.0, 'tenancy_id': 2320, 'protection_status': 'protected'}
  - {'id': 30, 'amount': 950.0, 'tenancy_id': 2322, 'protection_status': 'protected'}
  - {'id': 31, 'amount': 900.0, 'tenancy_id': 2323, 'protection_status': 'protected'}
  - {'id': 32, 'amount': 920.0, 'tenancy_id': 2325, 'protection_status': 'protected'}
---

### Maintenance records with NULL property_id
- **Count:** 163
```
SELECT mj.id, mj.reference, mj.title FROM maintenance_jobs mj
      WHERE mj.property_id IS NULL
```
- **Sample records (up to 10):**
  - {'id': 1, 'reference': None, 'title': 'Bricklane F4'}
  - {'id': 2, 'reference': None, 'title': 'Broken Chair'}
  - {'id': 3, 'reference': None, 'title': 'The Sink basin is blocked not able to wash dishes etc'}
  - {'id': 4, 'reference': None, 'title': 'Dead rodent (mouse I think) in back of sofa'}
  - {'id': 5, 'reference': None, 'title': 'Please, refer to my mail for the description of shower hose might need longer and new one, black rubber washer and shower head, faucet aerator missing, plus other repairs in room and kitchen'}
  - {'id': 6, 'reference': None, 'title': 'central bed support'}
  - {'id': 7, 'reference': None, 'title': 'Floorplans'}
  - {'id': 10, 'reference': None, 'title': 'FRA certificate'}
  - {'id': 11, 'reference': None, 'title': '2 Claremont Square - Recurring Water Leak'}
  - {'id': 12, 'reference': None, 'title': 'Install door number stickers on all properties'}
---

# 5. Data Integrity Issues

### Tenants linked to inactive properties
- **Count:** 0
```
SELECT t.id, t.first_name, t.last_name, t.property_id, p.name AS property_name, p.is_active
      FROM tenants t JOIN properties p ON t.property_id = p.id
      WHERE p.is_active = 0 OR p.is_active IS NULL
```
---

### Tenancies on archived/inactive properties
- **Count:** 0
```
SELECT tn.id, tn.ref, tn.property_id, p.name AS property_name, p.is_active
      FROM tenancies tn JOIN properties p ON tn.property_id = p.id
      WHERE p.is_active = 0 OR p.is_active IS NULL
```
---

### Overlapping active tenancies on same unit
- **Count:** 1
```
SELECT a.unit_id, a.id AS tenancy_a, a.start_date AS a_start, a.end_date AS a_end,
             b.id AS tenancy_b, b.start_date AS b_start, b.end_date AS b_end
      FROM tenancies a
      JOIN tenancies b ON a.unit_id = b.unit_id AND a.id < b.id
      WHERE a.status IN ('Active', 'active', 'Periodic', 'periodic')
        AND b.status IN ('Active', 'active', 'Periodic', 'periodic')
        AND a.start_date <= b.end_date AND b.start_date <= a.end_date
```
- **Sample records (up to 10):**
  - {'unit_id': 989, 'tenancy_a': 2756, 'a_start': '2026-08-01', 'a_end': '2027-02-01', 'tenancy_b': 2757, 'b_start': '2026-08-01', 'b_end': '2027-02-01'}
---

### Tenants with different property_id than their tenancy's property_id
- **Count:** 530
```
SELECT t.id, t.first_name, t.last_name, t.property_id AS tenant_property_id,
             tn.property_id AS tenancy_property_id, tn.id AS tenancy_id
      FROM tenants t JOIN tenancies tn ON t.tenancy_id = tn.id
      WHERE t.property_id IS NOT NULL AND tn.property_id IS NOT NULL
        AND t.property_id != tn.property_id
```
- **Sample records (up to 10):**
  - {'id': 2617, 'first_name': 'Safoora', 'last_name': 'Kumbalakkuzhi', 'tenant_property_id': 331625, 'tenancy_property_id': 249, 'tenancy_id': 2287}
  - {'id': 2618, 'first_name': 'Jeni', 'last_name': 'Mathew', 'tenant_property_id': 328079, 'tenancy_property_id': 255, 'tenancy_id': 2288}
  - {'id': 2619, 'first_name': 'Daniel', 'last_name': 'Ferrier', 'tenant_property_id': 330203, 'tenancy_property_id': 252, 'tenancy_id': 2289}
  - {'id': 2620, 'first_name': 'GURPREET', 'last_name': 'KAUR', 'tenant_property_id': 317213, 'tenancy_property_id': 262, 'tenancy_id': 2290}
  - {'id': 2621, 'first_name': 'Jayden', 'last_name': 'Newman', 'tenant_property_id': 324471, 'tenancy_property_id': 257, 'tenancy_id': 2291}
  - {'id': 2622, 'first_name': 'Tamara', 'last_name': 'Kubacka', 'tenant_property_id': 330203, 'tenancy_property_id': 252, 'tenancy_id': 2292}
  - {'id': 2623, 'first_name': 'KAMURUNNAHAR', 'last_name': 'MONY', 'tenant_property_id': 321959, 'tenancy_property_id': 260, 'tenancy_id': 2293}
  - {'id': 2624, 'first_name': 'SM  ASADUZZAMAN', 'last_name': 'KANOK', 'tenant_property_id': 321959, 'tenancy_property_id': 260, 'tenancy_id': 2293}
  - {'id': 2625, 'first_name': 'Shah Mohammad Samiul Kabir', 'last_name': 'Chowdhury', 'tenant_property_id': 321959, 'tenancy_property_id': 260, 'tenancy_id': 2293}
  - {'id': 2626, 'first_name': 'Méline', 'last_name': 'Desault', 'tenant_property_id': 308266, 'tenancy_property_id': 283, 'tenancy_id': 2294}
---

### Units with occupied status but no active tenancy
- **Count:** 9
```
SELECT u.id, u.unit_ref, u.unit_status, u.property_id
      FROM units u
      WHERE u.unit_status IN ('Let', 'Occupied', 'occupied', 'let')
        AND u.id NOT IN (
          SELECT DISTINCT unit_id FROM tenancies
          WHERE unit_id IS NOT NULL AND status IN ('Active', 'active', 'Periodic', 'periodic')
        )
```
- **Sample records (up to 10):**
  - {'id': 815, 'unit_ref': 'D5', 'unit_status': 'Let', 'property_id': 244}
  - {'id': 841, 'unit_ref': 'Flat 11, 29-31 Adelaide Road, London', 'unit_status': 'Let', 'property_id': 251}
  - {'id': 844, 'unit_ref': '95 Wheat Sheaf Close, E14 9UY (Isle of dogs)', 'unit_status': 'Let', 'property_id': 254}
  - {'id': 878, 'unit_ref': 'Flat 3', 'unit_status': 'Let', 'property_id': 265}
  - {'id': 879, 'unit_ref': '44 Park Grove', 'unit_status': 'Let', 'property_id': 266}
  - {'id': 945, 'unit_ref': 'M2', 'unit_status': 'Let', 'property_id': 284}
  - {'id': 946, 'unit_ref': 'D1', 'unit_status': 'Let', 'property_id': 284}
  - {'id': 961, 'unit_ref': 'Test Room 1', 'unit_status': 'Let', 'property_id': 241}
  - {'id': 962, 'unit_ref': 'Audit Room', 'unit_status': 'Let', 'property_id': 241}
---

### Units with vacant status but an active tenancy
- **Count:** 4
```
SELECT u.id, u.unit_ref, u.unit_status, u.property_id
      FROM units u
      WHERE u.unit_status IN ('Available', 'Vacant', 'available', 'vacant')
        AND u.id IN (
          SELECT DISTINCT unit_id FROM tenancies
          WHERE unit_id IS NOT NULL AND status IN ('Active', 'active', 'Periodic', 'periodic')
        )
```
- **Sample records (up to 10):**
  - {'id': 963, 'unit_ref': 'R1', 'unit_status': 'Available', 'property_id': 100001}
  - {'id': 982, 'unit_ref': 'U1', 'unit_status': 'Available', 'property_id': 100015}
  - {'id': 989, 'unit_ref': 'Room A', 'unit_status': 'Available', 'property_id': 100001}
  - {'id': 991, 'unit_ref': 'Room C', 'unit_status': 'Available', 'property_id': 100001}
---

# 6. Schema Issues

## 6.1 Primary Key Check

### Table `referencing_forms_backup` has no PRIMARY KEY
- **ISSUE:** Table `referencing_forms_backup` has NO primary key columns defined.
---

### Table `sqlite_sequence` has no PRIMARY KEY
- **ISSUE:** Table `sqlite_sequence` has NO primary key columns defined.
---

## 6.2 Timestamp Columns

### Table `access_records` missing `created` timestamp
- **ISSUE:** Table `access_records` has no `created` column.
---

### Table `access_records` missing `modified` timestamp
- **ISSUE:** Table `access_records` has no `modified` column.
---

### Table `activity_log` missing `modified` timestamp
- **ISSUE:** Table `activity_log` has no `modified` column.
---

### Table `comments` missing `modified` timestamp
- **ISSUE:** Table `comments` has no `modified` column.
---

### Table `company_settings` missing `created` timestamp
- **ISSUE:** Table `company_settings` has no `created` column.
---

### Table `company_settings` missing `modified` timestamp
- **ISSUE:** Table `company_settings` has no `modified` column.
---

### Table `conversation_timeline` missing `created` timestamp
- **ISSUE:** Table `conversation_timeline` has no `created` column.
---

### Table `conversation_timeline` missing `modified` timestamp
- **ISSUE:** Table `conversation_timeline` has no `modified` column.
---

### Table `documents` missing `modified` timestamp
- **ISSUE:** Table `documents` has no `modified` column.
---

### Table `esignature_audit_log` missing `created` timestamp
- **ISSUE:** Table `esignature_audit_log` has no `created` column.
---

### Table `esignature_audit_log` missing `modified` timestamp
- **ISSUE:** Table `esignature_audit_log` has no `modified` column.
---

### Table `esignature_requests` missing `modified` timestamp
- **ISSUE:** Table `esignature_requests` has no `modified` column.
---

### Table `form_sections` missing `created` timestamp
- **ISSUE:** Table `form_sections` has no `created` column.
---

### Table `form_sections` missing `modified` timestamp
- **ISSUE:** Table `form_sections` has no `modified` column.
---

### Table `invoices` missing `modified` timestamp
- **ISSUE:** Table `invoices` has no `modified` column.
---

### Table `ll_communications` missing `modified` timestamp
- **ISSUE:** Table `ll_communications` has no `modified` column.
---

### Table `messages` missing `modified` timestamp
- **ISSUE:** Table `messages` has no `modified` column.
---

### Table `migration_log` missing `created` timestamp
- **ISSUE:** Table `migration_log` has no `created` column.
---

### Table `migration_log` missing `modified` timestamp
- **ISSUE:** Table `migration_log` has no `modified` column.
---

### Table `notifications` missing `modified` timestamp
- **ISSUE:** Table `notifications` has no `modified` column.
---

### Table `portal_sessions` missing `modified` timestamp
- **ISSUE:** Table `portal_sessions` has no `modified` column.
---

### Table `property_images` missing `created` timestamp
- **ISSUE:** Table `property_images` has no `created` column.
---

### Table `property_images` missing `modified` timestamp
- **ISSUE:** Table `property_images` has no `modified` column.
---

### Table `referencing_checks` missing `modified` timestamp
- **ISSUE:** Table `referencing_checks` has no `modified` column.
---

### Table `referencing_documents` missing `created` timestamp
- **ISSUE:** Table `referencing_documents` has no `created` column.
---

### Table `referencing_documents` missing `modified` timestamp
- **ISSUE:** Table `referencing_documents` has no `modified` column.
---

### Table `sqlite_sequence` missing `created` timestamp
- **ISSUE:** Table `sqlite_sequence` has no `created` column.
---

### Table `sqlite_sequence` missing `modified` timestamp
- **ISSUE:** Table `sqlite_sequence` has no `modified` column.
---

### Table `sync_conflicts` missing `created` timestamp
- **ISSUE:** Table `sync_conflicts` has no `created` column.
---

### Table `sync_conflicts` missing `modified` timestamp
- **ISSUE:** Table `sync_conflicts` has no `modified` column.
---

### Table `tags` missing `created` timestamp
- **ISSUE:** Table `tags` has no `created` column.
---

### Table `tags` missing `modified` timestamp
- **ISSUE:** Table `tags` has no `modified` column.
---

## 6.3 Missing Indexes on FK Columns

### Table `tenancies` column `property_id` lacks index
- **ISSUE:** Column `tenancies.property_id` has no index.
---

### Table `tenants` column `property_id` lacks index
- **ISSUE:** Column `tenants.property_id` has no index.
---

### Table `maintenance_jobs` column `tenant_id` (FK to tenants) lacks index
- **ISSUE:** FK column `maintenance_jobs.tenant_id` → `tenants` has no index.
---

### Table `maintenance_jobs` column `property_id` (FK to properties) lacks index
- **ISSUE:** FK column `maintenance_jobs.property_id` → `properties` has no index.
---

### Table `maintenance_jobs` column `property_id` lacks index
- **ISSUE:** Column `maintenance_jobs.property_id` has no index.
---

### Table `maintenance_jobs` column `tenant_id` lacks index
- **ISSUE:** Column `maintenance_jobs.tenant_id` has no index.
---

### Table `maintenance_requests` column `property_id` lacks index
- **ISSUE:** Column `maintenance_requests.property_id` has no index.
---

### Table `maintenance_requests` column `tenancy_id` lacks index
- **ISSUE:** Column `maintenance_requests.tenancy_id` has no index.
---

### Table `applicants` column `unit_id` (FK to units) lacks index
- **ISSUE:** FK column `applicants.unit_id` → `units` has no index.
---

### Table `applicants` column `property_id` (FK to properties) lacks index
- **ISSUE:** FK column `applicants.property_id` → `properties` has no index.
---

### Table `applicants` column `property_id` lacks index
- **ISSUE:** Column `applicants.property_id` has no index.
---

### Table `applicants` column `unit_id` lacks index
- **ISSUE:** Column `applicants.unit_id` has no index.
---

### Table `invoices` column `tenant_id` (FK to tenants) lacks index
- **ISSUE:** FK column `invoices.tenant_id` → `tenants` has no index.
---

### Table `invoices` column `tenancy_id` (FK to tenancies) lacks index
- **ISSUE:** FK column `invoices.tenancy_id` → `tenancies` has no index.
---

### Table `invoices` column `tenancy_id` lacks index
- **ISSUE:** Column `invoices.tenancy_id` has no index.
---

### Table `invoices` column `tenant_id` lacks index
- **ISSUE:** Column `invoices.tenant_id` has no index.
---

# 7. Summary
| Category | Count |
| --- | --- |
| Total Orphan Records | 530 |
| Total Duplicate Records | 56 |
| Total Missing Relationships | 228 |
| Total Data Integrity Issues | 544 |
| Total Schema Issues | 50 |
| **TOTAL ISSUES** | 1408 |

## Per-Table Record Counts
| Table | Record Count |
| --- | --- |
| access_records | 11 |
| activity_log | 72 |
| applicants | 682 |
| comments | 5 |
| company_settings | 9 |
| conversation_timeline | 0 |
| deposits | 148 |
| documents | 1 |
| esignature_audit_log | 7 |
| esignature_requests | 1 |
| form_sections | 195 |
| guarantors | 4 |
| invoices | 2 |
| ll_communications | 0 |
| maintenance_jobs | 200 |
| maintenance_orders | 1 |
| maintenance_requests | 2 |
| message_threads | 2 |
| messages | 6 |
| migration_log | 1 |
| notifications | 25 |
| portal_sessions | 9 |
| portal_users | 2 |
| properties | 67 |
| property_images | 0 |
| property_owners | 2 |
| referencing_checks | 18 |
| referencing_documents | 0 |
| referencing_forms | 10 |
| referencing_forms_backup | 0 |
| rent_charges | 2084 |
| sqlite_sequence | 33 |
| sync_conflicts | 20 |
| tags | 13 |
| tenancies | 470 |
| tenants | 535 |
| transactions | 7293 |
| units | 193 |

*Audit completed at 2026-07-15T20:34:43.455423*
