-- ============================================================
-- SEED DATA: Last Expense Analytics Dashboard
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor > New Query)
-- Images/documents are nullable — skipped here
-- ============================================================

-- ── 1. GROUPS ───────────────────────────────────────────────
INSERT INTO groups (id, group_code, group_name, group_type, contact_person, contact_position, contact_phone, registered, created_at)
VALUES
  ('a1000000-0000-0000-0000-000000000001', 'GRP-TUKUF', 'Tukuza Welfare Group', 'welfare', 'Mary Akinyi', 'Chairperson', '0722100200', true, '2025-06-10T08:00:00Z'),
  ('a1000000-0000-0000-0000-000000000002', 'GRP-NEEMA', 'Neema Chama', 'chama', 'Peter Odhiambo', 'Secretary', '0733200300', true, '2025-07-15T09:30:00Z'),
  ('a1000000-0000-0000-0000-000000000003', 'GRP-UPEND', 'Upendo Church Fellowship', 'church', 'Rev. Daniel Mutua', 'Pastor', '0711300400', true, '2025-08-01T10:00:00Z'),
  ('a1000000-0000-0000-0000-000000000004', 'GRP-TUSCO', 'Tumaini Sacco Ltd', 'sacco', 'Jane Wanjiru', 'Manager', '0700400500', true, '2025-09-05T11:00:00Z'),
  ('a1000000-0000-0000-0000-000000000005', 'GRP-ALMNI', 'Starehe Alumni Association', 'alumni', 'George Kamau', 'President', '0788500600', false, '2025-10-20T14:00:00Z'),
  ('a1000000-0000-0000-0000-000000000006', 'GRP-UZIMA', 'Uzima Welfare Society', 'welfare', 'Agnes Njeri', 'Treasurer', '0722600700', true, '2025-11-12T08:45:00Z')
ON CONFLICT (id) DO NOTHING;


-- ── 2. APPLICATIONS (50 records, spread Nov 2025 – May 2026) ─
INSERT INTO last_expense_applications (id, ref, submitted_at, status, application_type, group_id, underwriter, cover_option, cover_amount, base_premium, extras_premium, total_premium, full_name, date_of_birth, gender, national_id, kra_pin, email, mobile, town, occupation, po_box, postal_code)
VALUES
-- ─── November 2025 ───
('b1000000-0000-0000-0000-000000000001', 'LE-ABSA01-A1B2C3', '2025-11-02T09:14:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000001', 'absa', 3, 200000, 4800, 1200, 6000, 'John Otieno Ouma', '1978-03-15', 'M', '23456789', 'A012345678Z', 'john.ouma@gmail.com', '0722111001', 'Nairobi', 'Teacher', '12345', '00100'),
('b1000000-0000-0000-0000-000000000002', 'LE-CPEX02-D4E5F6', '2025-11-05T11:30:00Z', 'approved', 'individual', NULL, 'capex', 2, 150000, 3600, 0, 3600, 'Grace Wanjiku Mwangi', '1985-07-22', 'F', '34567890', 'A023456789Z', 'grace.mwangi@yahoo.com', '0733222002', 'Thika', 'Nurse', NULL, NULL),
('b1000000-0000-0000-0000-000000000003', 'LE-ABSA03-G7H8I9', '2025-11-10T14:22:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000002', 'absa', 4, 300000, 7200, 1800, 9000, 'Samuel Kipchoge Korir', '1972-11-08', 'M', '45678901', 'A034567890Z', 'samuel.korir@outlook.com', '0711333003', 'Eldoret', 'Farmer', '5678', '30100'),
('b1000000-0000-0000-0000-000000000004', 'LE-CPEX04-J1K2L3', '2025-11-15T08:45:00Z', 'pending', 'individual', NULL, 'capex', 1, 100000, 2400, 0, 2400, 'Fatuma Hassan Ali', '1990-01-30', 'F', '56789012', 'A045678901Z', 'fatuma.ali@gmail.com', '0700444004', 'Mombasa', 'Trader', '9012', '80100'),
('b1000000-0000-0000-0000-000000000005', 'LE-ABSA05-M4N5O6', '2025-11-20T16:10:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000003', 'absa', 5, 400000, 9600, 2400, 12000, 'David Mwenda Kibet', '1968-05-12', 'M', '67890123', 'A056789012Z', 'david.kibet@gmail.com', '0788555005', 'Nakuru', 'Mechanic', NULL, NULL),
('b1000000-0000-0000-0000-000000000006', 'LE-CPEX06-P7Q8R9', '2025-11-25T10:05:00Z', 'rejected', 'individual', NULL, 'capex', 3, 200000, 4800, 600, 5400, 'Elizabeth Achieng Otieno', '1982-09-03', 'F', '78901234', 'A067890123Z', 'elizabeth.otieno@hotmail.com', '0722666006', 'Kisumu', 'Accountant', '3456', '40100'),

-- ─── December 2025 ───
('b1000000-0000-0000-0000-000000000007', 'LE-ABSA07-S1T2U3', '2025-12-01T09:00:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000001', 'absa', 4, 300000, 7200, 1800, 9000, 'Catherine Nyambura Kamau', '1975-12-20', 'F', '89012345', 'A078901234Z', 'catherine.kamau@gmail.com', '0733777007', 'Nairobi', 'Businesswoman', '7890', '00100'),
('b1000000-0000-0000-0000-000000000008', 'LE-CPEX08-V4W5X6', '2025-12-04T13:20:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000004', 'capex', 6, 500000, 12000, 3000, 15000, 'Michael Njoroge Maina', '1970-06-18', 'M', '90123456', 'A089012345Z', 'michael.maina@yahoo.com', '0711888008', 'Nyeri', 'Retired', NULL, NULL),
('b1000000-0000-0000-0000-000000000009', 'LE-ABSA09-Y7Z8A1', '2025-12-08T07:55:00Z', 'under_review', 'individual', NULL, 'absa', 2, 150000, 3600, 0, 3600, 'Amina Wafula Simiyu', '1988-04-25', 'F', '01234567', 'A090123456Z', 'amina.simiyu@gmail.com', '0700999009', 'Bungoma', 'Pharmacist', '2345', '50200'),
('b1000000-0000-0000-0000-000000000010', 'LE-CPEX10-B2C3D4', '2025-12-12T15:40:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000002', 'capex', 3, 200000, 4800, 1200, 6000, 'Joseph Omondi Onyango', '1980-08-14', 'M', '12345670', 'A101234567Z', 'joseph.onyango@gmail.com', '0722010010', 'Kisii', 'Driver', NULL, NULL),
('b1000000-0000-0000-0000-000000000011', 'LE-ABSA11-E5F6G7', '2025-12-16T11:15:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000003', 'absa', 7, 750000, 18000, 4500, 22500, 'Margaret Chebet Langat', '1965-02-28', 'F', '23456701', 'A112345670Z', 'margaret.langat@outlook.com', '0733020011', 'Kericho', 'Tea Farmer', '6789', '20200'),
('b1000000-0000-0000-0000-000000000012', 'LE-CPEX12-H8I9J1', '2025-12-20T09:30:00Z', 'pending', 'individual', NULL, 'capex', 1, 100000, 2400, 0, 2400, 'Brian Wekesa Simiyu', '1992-10-05', 'M', '34567012', 'A123456701Z', 'brian.wekesa@gmail.com', '0711030012', 'Kakamega', 'Boda Rider', NULL, NULL),
('b1000000-0000-0000-0000-000000000013', 'LE-ABSA13-K2L3M4', '2025-12-28T14:50:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000005', 'absa', 5, 400000, 9600, 2400, 12000, 'Alice Wambui Ngugi', '1977-07-10', 'F', '45670123', 'A134567012Z', 'alice.ngugi@gmail.com', '0700040013', 'Kiambu', 'Lecturer', '1234', '00900'),

-- ─── January 2026 ───
('b1000000-0000-0000-0000-000000000014', 'LE-ABSA14-N5O6P7', '2026-01-03T08:20:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000004', 'absa', 4, 300000, 7200, 1800, 9000, 'Patrick Kimani Gitau', '1974-09-20', 'M', '56701234', 'A145670123Z', 'patrick.gitau@yahoo.com', '0788050014', 'Nairobi', 'Engineer', '5670', '00100'),
('b1000000-0000-0000-0000-000000000015', 'LE-CPEX15-Q8R9S1', '2026-01-07T12:00:00Z', 'approved', 'individual', NULL, 'capex', 3, 200000, 4800, 600, 5400, 'Esther Auma Oloo', '1986-11-12', 'F', '67012345', 'A156701234Z', 'esther.oloo@gmail.com', '0722060015', 'Kisumu', 'Social Worker', NULL, NULL),
('b1000000-0000-0000-0000-000000000016', 'LE-ABSA16-T2U3V4', '2026-01-11T10:35:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000006', 'absa', 6, 500000, 12000, 3000, 15000, 'Robert Mutiso Musyoka', '1969-01-05', 'M', '70123456', 'A167012345Z', 'robert.musyoka@outlook.com', '0733070016', 'Machakos', 'Retired Civil Servant', '7012', '90100'),
('b1000000-0000-0000-0000-000000000017', 'LE-CPEX17-W5X6Y7', '2026-01-15T16:45:00Z', 'rejected', 'individual', NULL, 'capex', 2, 150000, 3600, 0, 3600, 'Nancy Jepkosgei Kiptoo', '1991-03-18', 'F', '01234560', 'A170123456Z', 'nancy.kiptoo@gmail.com', '0711080017', 'Nandi', 'Athlete', NULL, NULL),
('b1000000-0000-0000-0000-000000000018', 'LE-ABSA18-Z8A1B2', '2026-01-20T09:10:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000001', 'absa', 3, 200000, 4800, 1200, 6000, 'William Ochieng Odongo', '1983-06-28', 'M', '12345600', 'A181234560Z', 'william.odongo@gmail.com', '0700090018', 'Nairobi', 'Security Guard', NULL, NULL),
('b1000000-0000-0000-0000-000000000019', 'LE-CPEX19-C3D4E5', '2026-01-25T11:55:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000002', 'capex', 4, 300000, 7200, 1800, 9000, 'Lucy Moraa Nyamweya', '1979-12-01', 'F', '23456001', 'A192345600Z', 'lucy.moraa@yahoo.com', '0788100019', 'Kisii', 'Businesswoman', '2345', '40200'),
('b1000000-0000-0000-0000-000000000020', 'LE-ABSA20-F6G7H8', '2026-01-30T14:30:00Z', 'pending', 'individual', NULL, 'absa', 5, 400000, 9600, 0, 9600, 'Stephen Kariuki Njenga', '1971-04-07', 'M', '34560012', 'A203456001Z', 'stephen.njenga@gmail.com', '0722110020', 'Nairobi', 'Businessman', '3456', '00100'),

-- ─── February 2026 ───
('b1000000-0000-0000-0000-000000000021', 'LE-CPEX21-I9J1K2', '2026-02-03T08:40:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000003', 'capex', 2, 150000, 3600, 900, 4500, 'Ruth Nyokabi Wainaina', '1987-08-15', 'F', '45600123', 'A214560012Z', 'ruth.wainaina@gmail.com', '0733120021', 'Naivasha', 'Florist', NULL, NULL),
('b1000000-0000-0000-0000-000000000022', 'LE-ABSA22-L3M4N5', '2026-02-06T13:15:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000004', 'absa', 7, 750000, 18000, 4500, 22500, 'Charles Mwangi Wambugu', '1963-10-22', 'M', '56001234', 'A225600123Z', 'charles.wambugu@outlook.com', '0711130022', 'Nyahururu', 'Retired Banker', '5600', '20300'),
('b1000000-0000-0000-0000-000000000023', 'LE-CPEX23-O6P7Q8', '2026-02-10T10:00:00Z', 'approved', 'individual', NULL, 'capex', 3, 200000, 4800, 600, 5400, 'Mercy Atieno Owino', '1984-02-14', 'F', '60012345', 'A236001234Z', 'mercy.owino@gmail.com', '0700140023', 'Homa Bay', 'Tailor', NULL, NULL),
('b1000000-0000-0000-0000-000000000024', 'LE-ABSA24-R9S1T2', '2026-02-14T15:20:00Z', 'under_review', 'group', 'a1000000-0000-0000-0000-000000000005', 'absa', 4, 300000, 7200, 1800, 9000, 'Anthony Kiprop Rono', '1976-05-30', 'M', '00123456', 'A240012345Z', 'anthony.rono@yahoo.com', '0788150024', 'Iten', 'Coach', NULL, NULL),
('b1000000-0000-0000-0000-000000000025', 'LE-CPEX25-U3V4W5', '2026-02-18T09:45:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000006', 'capex', 5, 400000, 9600, 2400, 12000, 'Penina Muthoni Karanja', '1973-07-08', 'F', '01234500', 'A250123450Z', 'penina.karanja@gmail.com', '0722160025', 'Murang''a', 'Shop Owner', '0123', '10200'),
('b1000000-0000-0000-0000-000000000026', 'LE-ABSA26-X6Y7Z8', '2026-02-22T12:30:00Z', 'approved', 'individual', NULL, 'absa', 1, 100000, 2400, 0, 2400, 'Kevin Onyango Odhiambo', '1993-09-11', 'M', '12340056', 'A261234005Z', 'kevin.odhiambo@gmail.com', '0733170026', 'Siaya', 'Fisherman', NULL, NULL),
('b1000000-0000-0000-0000-000000000027', 'LE-CPEX27-A1B2C3', '2026-02-26T16:00:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000001', 'capex', 6, 500000, 12000, 3000, 15000, 'Dorcas Wanjala Barasa', '1967-11-25', 'F', '23400567', 'A272340056Z', 'dorcas.barasa@hotmail.com', '0711180027', 'Nairobi', 'Retired Teacher', '2340', '00100'),

-- ─── March 2026 ───
('b1000000-0000-0000-0000-000000000028', 'LE-ABSA28-D4E5F6', '2026-03-02T08:15:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000002', 'absa', 3, 200000, 4800, 1200, 6000, 'Timothy Wafula Masinde', '1981-01-19', 'M', '34005678', 'A283400567Z', 'timothy.masinde@gmail.com', '0700190028', 'Bungoma', 'Contractor', NULL, NULL),
('b1000000-0000-0000-0000-000000000029', 'LE-CPEX29-G7H8I9', '2026-03-06T11:40:00Z', 'rejected', 'individual', NULL, 'capex', 2, 150000, 3600, 0, 3600, 'Beatrice Chepkemoi Bett', '1989-06-03', 'F', '40056789', 'A294005678Z', 'beatrice.bett@gmail.com', '0788200029', 'Bomet', 'Nurse', NULL, NULL),
('b1000000-0000-0000-0000-000000000030', 'LE-ABSA30-J1K2L3', '2026-03-10T14:55:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000003', 'absa', 5, 400000, 9600, 2400, 12000, 'Francis Kariuki Mwaura', '1970-03-27', 'M', '00567890', 'A300056789Z', 'francis.mwaura@yahoo.com', '0722210030', 'Nairobi', 'Taxi Driver', '0056', '00100'),
('b1000000-0000-0000-0000-000000000031', 'LE-CPEX31-M4N5O6', '2026-03-14T09:25:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000004', 'capex', 4, 300000, 7200, 1800, 9000, 'Jane Akinyi Okoth', '1978-08-09', 'F', '05678901', 'A310056789Z', 'jane.okoth@gmail.com', '0733220031', 'Migori', 'Farmer', NULL, NULL),
('b1000000-0000-0000-0000-000000000032', 'LE-ABSA32-P7Q8R9', '2026-03-18T13:10:00Z', 'approved', 'individual', NULL, 'absa', 6, 500000, 12000, 0, 12000, 'Kenneth Mutua Kilonzo', '1966-12-14', 'M', '56789010', 'A320567890Z', 'kenneth.kilonzo@outlook.com', '0711230032', 'Kitui', 'Businessman', '5678', '90200'),
('b1000000-0000-0000-0000-000000000033', 'LE-CPEX33-S1T2U3', '2026-03-22T10:50:00Z', 'pending', 'group', 'a1000000-0000-0000-0000-000000000006', 'capex', 3, 200000, 4800, 1200, 6000, 'Gladys Wanjiru Githinji', '1984-04-16', 'F', '67890101', 'A336789010Z', 'gladys.githinji@gmail.com', '0700240033', 'Nairobi', 'Hair Stylist', NULL, NULL),
('b1000000-0000-0000-0000-000000000034', 'LE-ABSA34-V4W5X6', '2026-03-26T15:35:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000005', 'absa', 7, 750000, 18000, 4500, 22500, 'Philip Oduya Wanyama', '1962-07-20', 'M', '78901012', 'A347890101Z', 'philip.wanyama@gmail.com', '0788250034', 'Nairobi', 'Retired Judge', '7890', '00100'),

-- ─── April 2026 ───
('b1000000-0000-0000-0000-000000000035', 'LE-CPEX35-Y7Z8A1', '2026-04-01T08:30:00Z', 'approved', 'individual', NULL, 'capex', 1, 100000, 2400, 0, 2400, 'Rose Adhiambo Otieno', '1994-02-08', 'F', '89010123', 'A358901012Z', 'rose.otieno@gmail.com', '0722260035', 'Nairobi', 'Waitress', NULL, NULL),
('b1000000-0000-0000-0000-000000000036', 'LE-ABSA36-B2C3D4', '2026-04-04T12:15:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000001', 'absa', 4, 300000, 7200, 1800, 9000, 'James Ochieng Otieno', '1976-10-30', 'M', '90101234', 'A369010123Z', 'james.otieno2@yahoo.com', '0733270036', 'Nairobi', 'Plumber', NULL, NULL),
('b1000000-0000-0000-0000-000000000037', 'LE-CPEX37-E5F6G7', '2026-04-08T10:40:00Z', 'under_review', 'group', 'a1000000-0000-0000-0000-000000000002', 'capex', 5, 400000, 9600, 2400, 12000, 'Florence Nekesa Wafula', '1980-05-22', 'F', '01012345', 'A370101234Z', 'florence.wafula@gmail.com', '0711280037', 'Webuye', 'Shopkeeper', '0101', '50205'),
('b1000000-0000-0000-0000-000000000038', 'LE-ABSA38-H8I9J1', '2026-04-12T14:00:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000003', 'absa', 3, 200000, 4800, 1200, 6000, 'Peter Mwangi Nganga', '1973-09-14', 'M', '10123450', 'A381012345Z', 'peter.nganga@gmail.com', '0700290038', 'Nairobi', 'Carpenter', NULL, NULL),
('b1000000-0000-0000-0000-000000000039', 'LE-CPEX39-K2L3M4', '2026-04-16T09:20:00Z', 'approved', 'individual', NULL, 'capex', 2, 150000, 3600, 0, 3600, 'Sarah Jepkoech Cheruiyot', '1988-01-26', 'F', '01234501', 'A390123450Z', 'sarah.cheruiyot@gmail.com', '0788300039', 'Kapsabet', 'Lab Technician', NULL, NULL),
('b1000000-0000-0000-0000-000000000040', 'LE-ABSA40-N5O6P7', '2026-04-20T16:30:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000006', 'absa', 6, 500000, 12000, 3000, 15000, 'Daniel Otenyo Onyancha', '1968-06-11', 'M', '12345010', 'A401234501Z', 'daniel.onyancha@outlook.com', '0722310040', 'Kisii', 'Retired Headmaster', '1234', '40200'),
('b1000000-0000-0000-0000-000000000041', 'LE-CPEX41-Q8R9S1', '2026-04-24T11:50:00Z', 'pending', 'group', 'a1000000-0000-0000-0000-000000000004', 'capex', 4, 300000, 7200, 1800, 9000, 'Ann Wairimu Gichuki', '1982-12-03', 'F', '23450101', 'A412345010Z', 'ann.gichuki@gmail.com', '0733320041', 'Nanyuki', 'Hotel Manager', NULL, NULL),

-- ─── May 2026 ───
('b1000000-0000-0000-0000-000000000042', 'LE-ABSA42-T2U3V4', '2026-05-01T08:00:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000005', 'absa', 5, 400000, 9600, 2400, 12000, 'Julius Nyaberi Mogaka', '1975-04-18', 'M', '34501012', 'A423450101Z', 'julius.mogaka@gmail.com', '0711330042', 'Kisii', 'Matatu Owner', NULL, NULL),
('b1000000-0000-0000-0000-000000000043', 'LE-CPEX43-W5X6Y7', '2026-05-03T13:30:00Z', 'approved', 'individual', NULL, 'capex', 3, 200000, 4800, 600, 5400, 'Caroline Chelagat Tanui', '1986-08-07', 'F', '45010123', 'A434501012Z', 'caroline.tanui@yahoo.com', '0700340043', 'Eldoret', 'Physiotherapist', '4501', '30100'),
('b1000000-0000-0000-0000-000000000044', 'LE-ABSA44-Z8A1B2', '2026-05-06T10:15:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000001', 'absa', 4, 300000, 7200, 1800, 9000, 'Martin Ouma Owiti', '1979-11-29', 'M', '50101234', 'A444501012Z', 'martin.owiti@gmail.com', '0788350044', 'Nairobi', 'Sales Rep', NULL, NULL),
('b1000000-0000-0000-0000-000000000045', 'LE-CPEX45-C3D4E5', '2026-05-08T15:45:00Z', 'pending', 'group', 'a1000000-0000-0000-0000-000000000002', 'capex', 6, 500000, 12000, 3000, 15000, 'Jackline Nafula Simiyu', '1971-03-14', 'F', '01012340', 'A450101234Z', 'jackline.simiyu@gmail.com', '0722360045', 'Kitale', 'Retired Nurse', '0101', '30200'),
('b1000000-0000-0000-0000-000000000046', 'LE-ABSA46-F6G7H8', '2026-05-10T09:50:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000003', 'absa', 2, 150000, 3600, 900, 4500, 'Victor Opiyo Onyango', '1985-07-22', 'M', '10123400', 'A461012340Z', 'victor.onyango@gmail.com', '0733370046', 'Kisumu', 'Electrician', NULL, NULL),
('b1000000-0000-0000-0000-000000000047', 'LE-CPEX47-I9J1K2', '2026-05-12T12:20:00Z', 'under_review', 'individual', NULL, 'capex', 7, 750000, 18000, 0, 18000, 'Monica Wangari Njuguna', '1964-09-30', 'F', '01234001', 'A470123400Z', 'monica.njuguna@outlook.com', '0711380047', 'Nairobi', 'Director', '0123', '00100'),
('b1000000-0000-0000-0000-000000000048', 'LE-ABSA48-L3M4N5', '2026-05-14T14:10:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000006', 'absa', 5, 400000, 9600, 2400, 12000, 'Ernest Barasa Wanyonyi', '1972-01-08', 'M', '12340012', 'A481234001Z', 'ernest.wanyonyi@gmail.com', '0700390048', 'Trans-Nzoia', 'Farmer', NULL, NULL),
('b1000000-0000-0000-0000-000000000049', 'LE-CPEX49-O6P7Q8', '2026-05-15T10:30:00Z', 'approved', 'group', 'a1000000-0000-0000-0000-000000000004', 'capex', 3, 200000, 4800, 1200, 6000, 'Lilian Awuor Odera', '1983-05-17', 'F', '23400120', 'A492340012Z', 'lilian.odera@gmail.com', '0788400049', 'Nyeri', 'Banker', '2340', '10100'),
('b1000000-0000-0000-0000-000000000050', 'LE-ABSA50-R9S1T2', '2026-05-16T08:45:00Z', 'pending', 'individual', NULL, 'absa', 4, 300000, 7200, 0, 7200, 'Henry Kiplagat Kosgei', '1977-10-03', 'M', '34001230', 'A503400120Z', 'henry.kosgei@gmail.com', '0722410050', 'Uasin Gishu', 'Dairy Farmer', NULL, NULL)

ON CONFLICT (id) DO NOTHING;


-- ── 3. DEPENDENTS (120 records across all 50 applications) ───
INSERT INTO last_expense_dependents (id, application_id, client_id, relationship, full_name, date_of_birth, id_number, doc_type, mobile, is_biological, additional_premium, sort_order)
VALUES
-- App 1 (John Otieno) – 3 deps
('c1000000-0000-0000-0000-000000000001', 'b1000000-0000-0000-0000-000000000001', 'dep-0', 'spouse', 'Mary Akinyi Ouma', '1980-05-20', '24567890', 'national_id', '0722111101', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000002', 'b1000000-0000-0000-0000-000000000001', 'dep-1', 'child', 'Brian Otieno Ouma', '2005-08-14', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000003', 'b1000000-0000-0000-0000-000000000001', 'dep-2', 'mother', 'Mama Salome Otieno', '1952-03-10', '12345600', 'national_id', '0722111102', NULL, 600, 2),

-- App 2 (Grace Wanjiku) – 2 deps
('c1000000-0000-0000-0000-000000000004', 'b1000000-0000-0000-0000-000000000002', 'dep-0', 'child', 'Kevin Mwangi', '2010-11-03', NULL, 'birth_certificate', NULL, true, 0, 0),
('c1000000-0000-0000-0000-000000000005', 'b1000000-0000-0000-0000-000000000002', 'dep-1', 'child', 'Faith Wanjiku', '2013-04-18', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 3 (Samuel Kipchoge) – 4 deps
('c1000000-0000-0000-0000-000000000006', 'b1000000-0000-0000-0000-000000000003', 'dep-0', 'spouse', 'Jemimah Chebet Korir', '1975-09-12', '46789012', 'national_id', '0733200301', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000007', 'b1000000-0000-0000-0000-000000000003', 'dep-1', 'child', 'Sharon Jepchirchir', '2003-02-28', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000008', 'b1000000-0000-0000-0000-000000000003', 'dep-2', 'child', 'Emmanuel Kiprono', '2007-06-15', NULL, 'birth_certificate', NULL, true, 0, 2),
('c1000000-0000-0000-0000-000000000009', 'b1000000-0000-0000-0000-000000000003', 'dep-3', 'father', 'Mzee Korir Arap Bett', '1945-12-01', '11223344', 'national_id', NULL, NULL, 900, 3),

-- App 5 (David Mwenda) – 3 deps
('c1000000-0000-0000-0000-000000000010', 'b1000000-0000-0000-0000-000000000005', 'dep-0', 'spouse', 'Esther Wambui Kibet', '1972-04-08', '68901234', 'national_id', '0788555105', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000011', 'b1000000-0000-0000-0000-000000000005', 'dep-1', 'child', 'James Mwenda Jr', '2001-01-20', '99887766', 'national_id', '0711555205', true, 0, 1),
('c1000000-0000-0000-0000-000000000012', 'b1000000-0000-0000-0000-000000000005', 'dep-2', 'mother_in_law', 'Mama Agnes Wambui', '1948-07-15', '55443322', 'national_id', NULL, NULL, 1200, 2),

-- App 7 (Catherine Nyambura) – 3 deps
('c1000000-0000-0000-0000-000000000013', 'b1000000-0000-0000-0000-000000000007', 'dep-0', 'spouse', 'Paul Kamau Njoroge', '1973-10-05', '90123456', 'national_id', '0733777107', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000014', 'b1000000-0000-0000-0000-000000000007', 'dep-1', 'child', 'Dennis Kamau', '2008-03-22', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000015', 'b1000000-0000-0000-0000-000000000007', 'dep-2', 'father_in_law', 'Mzee Njoroge Maina', '1940-11-30', '33445566', 'national_id', NULL, NULL, 900, 2),

-- App 8 (Michael Njoroge) – 4 deps
('c1000000-0000-0000-0000-000000000016', 'b1000000-0000-0000-0000-000000000008', 'dep-0', 'spouse', 'Susan Nyambura Maina', '1972-02-14', '91234567', 'national_id', '0711888108', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000017', 'b1000000-0000-0000-0000-000000000008', 'dep-1', 'child', 'Victor Njoroge', '1998-07-09', '88776655', 'national_id', '0711888208', true, 0, 1),
('c1000000-0000-0000-0000-000000000018', 'b1000000-0000-0000-0000-000000000008', 'dep-2', 'child', 'Charity Wanjiru', '2002-12-25', NULL, 'birth_certificate', NULL, true, 0, 2),
('c1000000-0000-0000-0000-000000000019', 'b1000000-0000-0000-0000-000000000008', 'dep-3', 'mother', 'Mama Wanjiku Maina', '1944-06-18', '22334455', 'national_id', NULL, NULL, 1500, 3),

-- App 10 (Joseph Omondi) – 2 deps
('c1000000-0000-0000-0000-000000000020', 'b1000000-0000-0000-0000-000000000010', 'dep-0', 'spouse', 'Millicent Achieng Onyango', '1982-11-28', '13456780', 'national_id', '0722010110', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000021', 'b1000000-0000-0000-0000-000000000010', 'dep-1', 'child', 'Trevor Omondi', '2012-05-16', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 11 (Margaret Chebet) – 4 deps
('c1000000-0000-0000-0000-000000000022', 'b1000000-0000-0000-0000-000000000011', 'dep-0', 'spouse', 'Wilson Langat Koech', '1963-08-20', '24567801', 'national_id', '0733020111', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000023', 'b1000000-0000-0000-0000-000000000011', 'dep-1', 'child', 'Mercy Jepchirchir', '1995-01-12', '77665544', 'national_id', '0733020211', true, 0, 1),
('c1000000-0000-0000-0000-000000000024', 'b1000000-0000-0000-0000-000000000011', 'dep-2', 'child', 'Collins Kiprotich', '1998-09-05', '66554433', 'national_id', '0733020311', true, 0, 2),
('c1000000-0000-0000-0000-000000000025', 'b1000000-0000-0000-0000-000000000011', 'dep-3', 'grandparent', 'Kogo Tapsubei', '1935-04-01', '11002233', 'national_id', NULL, NULL, 2250, 3),

-- App 13 (Alice Wambui) – 3 deps
('c1000000-0000-0000-0000-000000000026', 'b1000000-0000-0000-0000-000000000013', 'dep-0', 'spouse', 'Joseph Ngugi Mwangi', '1975-03-15', '46701234', 'national_id', '0700040113', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000027', 'b1000000-0000-0000-0000-000000000013', 'dep-1', 'child', 'Ian Ngugi', '2006-10-22', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000028', 'b1000000-0000-0000-0000-000000000013', 'dep-2', 'sibling', 'Grace Wambui Ngugi', '1980-06-18', '47801234', 'national_id', '0700040213', NULL, 1200, 2),

-- App 14 (Patrick Kimani) – 3 deps
('c1000000-0000-0000-0000-000000000029', 'b1000000-0000-0000-0000-000000000014', 'dep-0', 'spouse', 'Joyce Muthoni Gitau', '1978-05-10', '57812345', 'national_id', '0788050114', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000030', 'b1000000-0000-0000-0000-000000000014', 'dep-1', 'child', 'Tracy Wambui Kimani', '2009-07-30', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000031', 'b1000000-0000-0000-0000-000000000014', 'dep-2', 'father', 'Mzee Gitau wa Mwangi', '1943-02-22', '11234567', 'national_id', NULL, NULL, 900, 2),

-- App 16 (Robert Mutiso) – 4 deps
('c1000000-0000-0000-0000-000000000032', 'b1000000-0000-0000-0000-000000000016', 'dep-0', 'spouse', 'Tabitha Mwikali Musyoka', '1972-08-25', '71234567', 'national_id', '0733070116', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000033', 'b1000000-0000-0000-0000-000000000016', 'dep-1', 'child', 'Alex Mutiso', '2000-04-12', '87654321', 'national_id', '0733070216', true, 0, 1),
('c1000000-0000-0000-0000-000000000034', 'b1000000-0000-0000-0000-000000000016', 'dep-2', 'child', 'Mercy Ndinda', '2004-11-08', NULL, 'birth_certificate', NULL, true, 0, 2),
('c1000000-0000-0000-0000-000000000035', 'b1000000-0000-0000-0000-000000000016', 'dep-3', 'mother', 'Mama Kalekye Mutiso', '1940-01-15', '11122233', 'national_id', NULL, NULL, 1500, 3),

-- App 18 (William Ochieng) – 2 deps
('c1000000-0000-0000-0000-000000000036', 'b1000000-0000-0000-0000-000000000018', 'dep-0', 'spouse', 'Janet Akinyi Odongo', '1985-03-28', '12456700', 'national_id', '0700090118', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000037', 'b1000000-0000-0000-0000-000000000018', 'dep-1', 'child', 'Baby Ryan Ochieng', '2018-09-10', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 19 (Lucy Moraa) – 3 deps
('c1000000-0000-0000-0000-000000000038', 'b1000000-0000-0000-0000-000000000019', 'dep-0', 'spouse', 'Thomas Nyamweya Omari', '1977-07-14', '24560012', 'national_id', '0788100119', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000039', 'b1000000-0000-0000-0000-000000000019', 'dep-1', 'child', 'Cynthia Moraa', '2005-12-20', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000040', 'b1000000-0000-0000-0000-000000000019', 'dep-2', 'mother_in_law', 'Mama Nyamweya', '1950-04-05', '33445501', 'national_id', NULL, NULL, 900, 2),

-- App 21 (Ruth Nyokabi) – 2 deps
('c1000000-0000-0000-0000-000000000041', 'b1000000-0000-0000-0000-000000000021', 'dep-0', 'child', 'Ashley Wainaina', '2014-06-12', NULL, 'birth_certificate', NULL, true, 0, 0),
('c1000000-0000-0000-0000-000000000042', 'b1000000-0000-0000-0000-000000000021', 'dep-1', 'mother', 'Mama Wainaina', '1958-10-30', '44556600', 'national_id', NULL, NULL, 450, 1),

-- App 22 (Charles Mwangi) – 4 deps
('c1000000-0000-0000-0000-000000000043', 'b1000000-0000-0000-0000-000000000022', 'dep-0', 'spouse', 'Sophia Nyambura Wambugu', '1965-05-18', '57012345', 'national_id', '0711130122', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000044', 'b1000000-0000-0000-0000-000000000022', 'dep-1', 'child', 'Edwin Mwangi', '1993-08-25', '76543210', 'national_id', '0711130222', true, 0, 1),
('c1000000-0000-0000-0000-000000000045', 'b1000000-0000-0000-0000-000000000022', 'dep-2', 'child', 'Winnie Njeri', '1996-02-14', '65432109', 'national_id', '0711130322', true, 0, 2),
('c1000000-0000-0000-0000-000000000046', 'b1000000-0000-0000-0000-000000000022', 'dep-3', 'father_in_law', 'Mzee Wambugu Karanja', '1936-09-07', '11223300', 'national_id', NULL, NULL, 2250, 3),

-- App 25 (Penina Muthoni) – 3 deps
('c1000000-0000-0000-0000-000000000047', 'b1000000-0000-0000-0000-000000000025', 'dep-0', 'spouse', 'John Karanja Mwangi', '1971-11-08', '02345001', 'national_id', '0722160125', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000048', 'b1000000-0000-0000-0000-000000000025', 'dep-1', 'child', 'Diana Muthoni', '2004-03-15', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000049', 'b1000000-0000-0000-0000-000000000025', 'dep-2', 'sibling', 'Agnes Njeri Karanja', '1976-07-22', '03456012', 'national_id', '0722160225', NULL, 1200, 2),

-- App 27 (Dorcas Wanjala) – 3 deps
('c1000000-0000-0000-0000-000000000050', 'b1000000-0000-0000-0000-000000000027', 'dep-0', 'child', 'Samuel Barasa', '1992-04-30', '78901200', 'national_id', '0711180127', true, 0, 0),
('c1000000-0000-0000-0000-000000000051', 'b1000000-0000-0000-0000-000000000027', 'dep-1', 'child', 'Rebecca Nafula', '1995-01-18', '67890100', 'national_id', '0711180227', true, 0, 1),
('c1000000-0000-0000-0000-000000000052', 'b1000000-0000-0000-0000-000000000027', 'dep-2', 'grandparent', 'Koko Naliaka Barasa', '1938-08-05', '22334401', 'national_id', NULL, NULL, 1500, 2),

-- App 28 (Timothy Wafula) – 2 deps
('c1000000-0000-0000-0000-000000000053', 'b1000000-0000-0000-0000-000000000028', 'dep-0', 'spouse', 'Sarah Nekesa Masinde', '1983-06-20', '35006789', 'national_id', '0700190128', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000054', 'b1000000-0000-0000-0000-000000000028', 'dep-1', 'child', 'Brian Wafula Jr', '2011-10-15', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 30 (Francis Kariuki) – 3 deps
('c1000000-0000-0000-0000-000000000055', 'b1000000-0000-0000-0000-000000000030', 'dep-0', 'spouse', 'Wanjiru Mwaura', '1973-02-14', '01678901', 'national_id', '0722210130', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000056', 'b1000000-0000-0000-0000-000000000030', 'dep-1', 'child', 'Victor Mwaura', '2003-05-08', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000057', 'b1000000-0000-0000-0000-000000000030', 'dep-2', 'mother', 'Mama Wangari Kariuki', '1942-11-22', '00112233', 'national_id', NULL, NULL, 1200, 2),

-- App 31 (Jane Akinyi) – 2 deps
('c1000000-0000-0000-0000-000000000058', 'b1000000-0000-0000-0000-000000000031', 'dep-0', 'spouse', 'Richard Okoth Omondi', '1976-09-03', '06789012', 'national_id', '0733220131', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000059', 'b1000000-0000-0000-0000-000000000031', 'dep-1', 'child', 'Christine Akinyi', '2010-07-26', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 34 (Philip Oduya) – 4 deps
('c1000000-0000-0000-0000-000000000060', 'b1000000-0000-0000-0000-000000000034', 'dep-0', 'spouse', 'Dorothy Nanjala Wanyama', '1965-03-28', '79012012', 'national_id', '0788250134', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000061', 'b1000000-0000-0000-0000-000000000034', 'dep-1', 'child', 'Vincent Wanyama', '1990-12-10', '65432100', 'national_id', '0788250234', true, 0, 1),
('c1000000-0000-0000-0000-000000000062', 'b1000000-0000-0000-0000-000000000034', 'dep-2', 'child', 'Patricia Oduya', '1993-06-15', '54321009', 'national_id', '0788250334', true, 0, 2),
('c1000000-0000-0000-0000-000000000063', 'b1000000-0000-0000-0000-000000000034', 'dep-3', 'father', 'Mzee Oduya Ingutia', '1932-01-20', '00998877', 'national_id', NULL, NULL, 2250, 3),

-- App 36 (James Ochieng) – 2 deps
('c1000000-0000-0000-0000-000000000064', 'b1000000-0000-0000-0000-000000000036', 'dep-0', 'spouse', 'Pamela Adhiambo Otieno', '1979-08-14', '91012345', 'national_id', '0733270136', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000065', 'b1000000-0000-0000-0000-000000000036', 'dep-1', 'child', 'Trevor Ochieng', '2012-02-28', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 37 (Florence Nekesa) – 3 deps
('c1000000-0000-0000-0000-000000000066', 'b1000000-0000-0000-0000-000000000037', 'dep-0', 'spouse', 'Andrew Wafula Barasa', '1978-12-05', '02012345', 'national_id', '0711280137', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000067', 'b1000000-0000-0000-0000-000000000037', 'dep-1', 'child', 'Joy Nekesa', '2007-04-18', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000068', 'b1000000-0000-0000-0000-000000000037', 'dep-2', 'mother', 'Mama Nasimiyu Wafula', '1950-09-12', '44556612', 'national_id', NULL, NULL, 1200, 2),

-- App 38 (Peter Mwangi Nganga) – 3 deps
('c1000000-0000-0000-0000-000000000069', 'b1000000-0000-0000-0000-000000000038', 'dep-0', 'spouse', 'Hannah Njeri Nganga', '1976-01-22', '11234500', 'national_id', '0700290138', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000070', 'b1000000-0000-0000-0000-000000000038', 'dep-1', 'child', 'Ian Nganga', '2008-11-30', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000071', 'b1000000-0000-0000-0000-000000000038', 'dep-2', 'father_in_law', 'Mzee Nganga Karuri', '1941-05-18', '00445566', 'national_id', NULL, NULL, 600, 2),

-- App 40 (Daniel Otenyo) – 4 deps
('c1000000-0000-0000-0000-000000000072', 'b1000000-0000-0000-0000-000000000040', 'dep-0', 'spouse', 'Josephine Kemunto Onyancha', '1970-10-14', '13456010', 'national_id', '0722310140', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000073', 'b1000000-0000-0000-0000-000000000040', 'dep-1', 'child', 'Kevin Otenyo', '1997-03-08', '76543200', 'national_id', '0722310240', true, 0, 1),
('c1000000-0000-0000-0000-000000000074', 'b1000000-0000-0000-0000-000000000040', 'dep-2', 'child', 'Brenda Kemunto', '2001-08-22', NULL, 'birth_certificate', NULL, true, 0, 2),
('c1000000-0000-0000-0000-000000000075', 'b1000000-0000-0000-0000-000000000040', 'dep-3', 'mother', 'Mama Kerubo Onyancha', '1940-12-01', '00223344', 'national_id', NULL, NULL, 1500, 3),

-- App 42 (Julius Nyaberi) – 2 deps
('c1000000-0000-0000-0000-000000000076', 'b1000000-0000-0000-0000-000000000042', 'dep-0', 'spouse', 'Rachel Bosibori Mogaka', '1977-06-20', '35012345', 'national_id', '0711330142', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000077', 'b1000000-0000-0000-0000-000000000042', 'dep-1', 'child', 'Dennis Nyaberi', '2005-09-14', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 44 (Martin Ouma) – 3 deps
('c1000000-0000-0000-0000-000000000078', 'b1000000-0000-0000-0000-000000000044', 'dep-0', 'spouse', 'Elizabeth Akinyi Owiti', '1981-04-15', '51012340', 'national_id', '0788350144', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000079', 'b1000000-0000-0000-0000-000000000044', 'dep-1', 'child', 'Leon Ouma', '2010-08-03', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000080', 'b1000000-0000-0000-0000-000000000044', 'dep-2', 'sibling', 'George Ouma Owiti', '1982-01-28', '52012340', 'national_id', '0788350244', NULL, 900, 2),

-- App 45 (Jackline Nafula) – 3 deps
('c1000000-0000-0000-0000-000000000081', 'b1000000-0000-0000-0000-000000000045', 'dep-0', 'spouse', 'Nicholas Simiyu Wekesa', '1969-09-22', '02012340', 'national_id', '0722360145', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000082', 'b1000000-0000-0000-0000-000000000045', 'dep-1', 'child', 'Brian Simiyu', '1996-05-10', '76540123', 'national_id', '0722360245', true, 0, 1),
('c1000000-0000-0000-0000-000000000083', 'b1000000-0000-0000-0000-000000000045', 'dep-2', 'mother_in_law', 'Mama Simiyu', '1942-03-14', '11002200', 'national_id', NULL, NULL, 1500, 2),

-- App 46 (Victor Opiyo) – 2 deps
('c1000000-0000-0000-0000-000000000084', 'b1000000-0000-0000-0000-000000000046', 'dep-0', 'spouse', 'Lillian Auma Onyango', '1987-05-30', '11234001', 'national_id', '0733370146', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000085', 'b1000000-0000-0000-0000-000000000046', 'dep-1', 'child', 'Baby Michelle Opiyo', '2020-01-15', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 48 (Ernest Barasa) – 3 deps
('c1000000-0000-0000-0000-000000000086', 'b1000000-0000-0000-0000-000000000048', 'dep-0', 'spouse', 'Hellen Nekesa Wanyonyi', '1974-08-12', '13340012', 'national_id', '0700390148', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000087', 'b1000000-0000-0000-0000-000000000048', 'dep-1', 'child', 'Sharon Barasa', '2002-06-25', NULL, 'birth_certificate', NULL, true, 0, 1),
('c1000000-0000-0000-0000-000000000088', 'b1000000-0000-0000-0000-000000000048', 'dep-2', 'father', 'Mzee Wanyonyi Masai', '1938-11-08', '00556677', 'national_id', NULL, NULL, 1200, 2),

-- App 49 (Lilian Awuor) – 2 deps
('c1000000-0000-0000-0000-000000000089', 'b1000000-0000-0000-0000-000000000049', 'dep-0', 'spouse', 'Mark Odera Ochieng', '1981-02-18', '24400123', 'national_id', '0788400149', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000090', 'b1000000-0000-0000-0000-000000000049', 'dep-1', 'child', 'Baby Joy Odera', '2019-12-05', NULL, 'birth_certificate', NULL, true, 0, 1),

-- Additional deps for more variety in group apps

-- App 4 (Fatuma Hassan) – 1 dep
('c1000000-0000-0000-0000-000000000091', 'b1000000-0000-0000-0000-000000000004', 'dep-0', 'child', 'Amira Hassan', '2015-03-22', NULL, 'birth_certificate', NULL, true, 0, 0),

-- App 9 (Amina Wafula) – 2 deps
('c1000000-0000-0000-0000-000000000092', 'b1000000-0000-0000-0000-000000000009', 'dep-0', 'child', 'Aisha Simiyu', '2016-07-14', NULL, 'birth_certificate', NULL, true, 0, 0),
('c1000000-0000-0000-0000-000000000093', 'b1000000-0000-0000-0000-000000000009', 'dep-1', 'mother', 'Mama Wafula', '1955-12-20', '55667700', 'national_id', NULL, NULL, 0, 1),

-- App 15 (Esther Auma) – 2 deps
('c1000000-0000-0000-0000-000000000094', 'b1000000-0000-0000-0000-000000000015', 'dep-0', 'child', 'Ryan Oloo', '2012-09-08', NULL, 'birth_certificate', NULL, true, 0, 0),
('c1000000-0000-0000-0000-000000000095', 'b1000000-0000-0000-0000-000000000015', 'dep-1', 'child', 'Stacy Auma', '2015-04-28', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 20 (Stephen Kariuki) – 2 deps
('c1000000-0000-0000-0000-000000000096', 'b1000000-0000-0000-0000-000000000020', 'dep-0', 'spouse', 'Christine Wanjiru Njenga', '1974-06-18', '35601234', 'national_id', '0722110120', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000097', 'b1000000-0000-0000-0000-000000000020', 'dep-1', 'child', 'Adrian Kariuki', '2008-01-30', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 23 (Mercy Atieno) – 1 dep
('c1000000-0000-0000-0000-000000000098', 'b1000000-0000-0000-0000-000000000023', 'dep-0', 'child', 'Baby Ethan Owino', '2020-05-16', NULL, 'birth_certificate', NULL, true, 0, 0),

-- App 26 (Kevin Onyango) – 1 dep
('c1000000-0000-0000-0000-000000000099', 'b1000000-0000-0000-0000-000000000026', 'dep-0', 'mother', 'Mama Odhiambo', '1960-03-10', '66778800', 'national_id', '0733170126', NULL, 0, 0),

-- App 32 (Kenneth Mutua) – 3 deps
('c1000000-0000-0000-0000-000000000100', 'b1000000-0000-0000-0000-000000000032', 'dep-0', 'spouse', 'Eunice Mwende Kilonzo', '1969-07-05', '57890101', 'national_id', '0711230132', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000101', 'b1000000-0000-0000-0000-000000000032', 'dep-1', 'child', 'Dennis Mutua', '1997-11-22', '76543201', 'national_id', '0711230232', true, 0, 1),
('c1000000-0000-0000-0000-000000000102', 'b1000000-0000-0000-0000-000000000032', 'dep-2', 'child', 'Diana Mwende', '2001-03-18', NULL, 'birth_certificate', NULL, true, 0, 2),

-- App 33 (Gladys Wanjiru) – 2 deps
('c1000000-0000-0000-0000-000000000103', 'b1000000-0000-0000-0000-000000000033', 'dep-0', 'spouse', 'Martin Githinji Mwangi', '1982-10-08', '68901012', 'national_id', '0700240133', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000104', 'b1000000-0000-0000-0000-000000000033', 'dep-1', 'child', 'Baby Jayden Githinji', '2021-02-14', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 35 (Rose Adhiambo) – 1 dep
('c1000000-0000-0000-0000-000000000105', 'b1000000-0000-0000-0000-000000000035', 'dep-0', 'child', 'Baby Angel Otieno', '2022-08-20', NULL, 'birth_certificate', NULL, true, 0, 0),

-- App 39 (Sarah Jepkoech) – 1 dep
('c1000000-0000-0000-0000-000000000106', 'b1000000-0000-0000-0000-000000000039', 'dep-0', 'mother', 'Mama Cheruiyot', '1956-04-22', '77889900', 'national_id', NULL, NULL, 0, 0),

-- App 41 (Ann Wairimu) – 2 deps
('c1000000-0000-0000-0000-000000000107', 'b1000000-0000-0000-0000-000000000041', 'dep-0', 'spouse', 'Edward Gichuki Mwangi', '1980-03-14', '24501234', 'national_id', '0733320141', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000108', 'b1000000-0000-0000-0000-000000000041', 'dep-1', 'child', 'Tiffany Wairimu', '2013-11-30', NULL, 'birth_certificate', NULL, true, 0, 1),

-- App 43 (Caroline Chelagat) – 2 deps
('c1000000-0000-0000-0000-000000000109', 'b1000000-0000-0000-0000-000000000043', 'dep-0', 'child', 'Liam Tanui', '2017-06-08', NULL, 'birth_certificate', NULL, true, 0, 0),
('c1000000-0000-0000-0000-000000000110', 'b1000000-0000-0000-0000-000000000043', 'dep-1', 'father', 'Mzee Tanui Arap Cheruiyot', '1950-01-12', '44556601', 'national_id', NULL, NULL, 300, 1),

-- App 47 (Monica Wangari) – 3 deps
('c1000000-0000-0000-0000-000000000111', 'b1000000-0000-0000-0000-000000000047', 'dep-0', 'spouse', 'Bernard Njuguna Karanja', '1962-11-25', '02340012', 'national_id', '0711380147', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000112', 'b1000000-0000-0000-0000-000000000047', 'dep-1', 'child', 'Karen Wangari', '1990-05-18', '87654300', 'national_id', '0711380247', true, 0, 1),
('c1000000-0000-0000-0000-000000000113', 'b1000000-0000-0000-0000-000000000047', 'dep-2', 'grandparent', 'Cucu Njuguna', '1930-07-08', '00112200', 'national_id', NULL, NULL, 0, 2),

-- App 50 (Henry Kiplagat) – 2 deps
('c1000000-0000-0000-0000-000000000114', 'b1000000-0000-0000-0000-000000000050', 'dep-0', 'spouse', 'Linet Jepkorir Kosgei', '1979-08-30', '35001230', 'national_id', '0722410150', NULL, 0, 0),
('c1000000-0000-0000-0000-000000000115', 'b1000000-0000-0000-0000-000000000050', 'dep-1', 'child', 'Ryan Kiplagat', '2011-04-12', NULL, 'birth_certificate', NULL, true, 0, 1)

ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- DONE! Summary:
--   6 groups
--  50 applications (7 months, 2 underwriters, all cover options, mixed statuses)
-- 115 dependents (spouses, children, parents, siblings, grandparents)
-- ============================================================
