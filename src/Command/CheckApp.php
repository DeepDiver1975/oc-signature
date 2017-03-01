<?php
/**
 * @author Lukas Reschke <lukas@statuscode.ch>
 *
 * @copyright Copyright (c) 2016, ownCloud GmbH.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */
namespace OC\Signature\Command;

use OC\Signature\Checker;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Output\OutputInterface;

class CheckApp extends Command {

	/**
	 * @var Checker
	 */
	private $checker;

	public function __construct(Checker $checker) {
		parent::__construct();
		$this->checker = $checker;
	}
	
	/**
	 * {@inheritdoc }
	 */
	protected function configure() {
		parent::configure();
		$this
			->setName('check-app')
			->setDescription('Check integrity of an app using a signature.')
			->addArgument('appid', null, InputArgument::REQUIRED, 'Application to check')
			->addArgument('path', null, InputArgument::REQUIRED, 'Path to application');
	}

	/**
	 * {@inheritdoc }
	 */
	protected function execute(InputInterface $input, OutputInterface $output) {
		$appid = $input->getArgument('appid');
		$path = $input->getArgument('path');
		$result = $this->checker->verifyAppSignature($appid, $path);
        $output->writeln(json_encode($result, JSON_PRETTY_PRINT));
		if (count($result)>0){
			return 1;
		}
		return 0;
	}

}
