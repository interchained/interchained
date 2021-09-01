--
-- Table structure for table `crypto_payments`
--

CREATE TABLE IF NOT EXISTS `crypto_payments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL DEFAULT '0',
  `orderID` varchar(250) NOT NULL,
  `productID` varchar(250)  DEFAULT NULL,
  `paymentID` varchar(250)  DEFAULT NULL,
  `amount` varchar(250) DEFAULT NULL,
  `amountUSD` varchar(250) DEFAULT NULL,
  `boxType` varchar(250) DEFAULT NULL,
  `address` varchar(250) DEFAULT NULL,
  `txID` varchar(250) DEFAULT NULL,
  `coinLabel` varchar(250) DEFAULT NULL,
  `txConfirmed` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `txDate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `processed` int(11) NOT NULL DEFAULT '0',
  `paid` int(11) NOT NULL DEFAULT '0',
  `expired` int(11) NOT NULL DEFAULT '0',
  `invoice_time` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;

